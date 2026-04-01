import threading
import re
import json


class MetricRegistry(object):
    def __init__(self):
        self._lock = threading.Lock()
        self._metrics = []

    def register(self, metric):
        with self._lock:
            self._metrics += [metric]

    def collect(self):
        with self._lock:
            lines = []
            for m in self._metrics:
                l = m.describe()
                if l:
                    lines += l
            if lines:
                return bytes("\n".join(lines) + "\n", "utf-8")


REGISTRY = MetricRegistry()

LABEL_NAME_PATTERN = re.compile("^[a-zA-Z_:][a-zA-Z0-9_:]*$")

INF = float("inf")


class Metric(object):

    _type = None

    def __init__(
        self,
        name,
        description=None,
        label_names=None,
        registry=REGISTRY,
        suffix=None,
        _label_values=None,
    ):
        self.name = name
        self.description = description
        self.suffix = suffix or ""

        self._labelnames = Metric._validated_labelnames(label_names)
        self._registry = registry
        self._labelvalues = _label_values or ()
        self._value = 0
        self._childs = {}
        self._lock = threading.Lock()
        # Register the metric family with the registry
        if not self._labelvalues:
            self._registry.register(self)

    def _header(self):
        return [
            f"# description {self.name} {self.description}",
            f"# TYPE {self.name} {self._type}",
        ]

    @staticmethod
    def _validated_labelnames(labelnames):
        if labelnames is None:
            return ()
        for l in labelnames:
            if not LABEL_NAME_PATTERN.match(l):
                return ValueError(
                    f"Invalid label name {l}. Must match {LABEL_NAME_PATTERN}"
                )
        return tuple(labelnames)

    def _is_observable(self):
        return not self._labelnames or (self._labelnames and self._labelvalues)

    def _raise_if_not_observable(self):
        if not self._is_observable():
            raise ValueError(
                "{} metric is missing label values actual={}, expected={}".format(
                    str(self._type), len(self._labelvalues), len(self._labelnames)
                )
            )

    @staticmethod
    def _label_value(v):
        if v == INF:
            return "+Inf"
        return json.dumps(v)

    def _render_labels(self):
        labels = []
        for i in range(len(self._labelnames)):
            labels += [
                f"{self._labelnames[i]}={Metric._label_value(self._labelvalues[i])}"
            ]
        return labels

    def _with_labels(self, labelnames, labelvalues):
        if len(labelvalues) != len(labelnames):
            raise ValueError(
                f"Incorrect label count: actual={len(labelvalues)}, expected={len(labelnames)}"
            )
        if labelvalues in self._childs:
            return self._childs[labelvalues]
        metric = self.__class__(
            self.name,
            description=self.description,
            label_names=labelnames,
            registry=self._registry,
            _label_values=labelvalues,
        )
        self._childs[labelvalues] = metric
        return metric

    def render_values(self):
        if self._childs:
            # return all metrics stored in the metrics family
            lines = []
            for _, m in self._childs.items():
                v = m.render_values()
                if v:
                    lines += v
            return lines
        if not self._labelvalues:
            return
        labels = self._render_labels()
        v = self._value
        if callable(self._value):
            v = self._value()
        return [f"{self.name}{self.suffix}{{{", ".join(labels)}}} {v}"]

    def set_value(self, value):
        self._raise_if_not_observable()
        with self._lock:
            self._value = value

    def inc(self, amount=1):
        self.set_value(self._value + amount)

    def set_function(self, f):
        if not callable(f):
            raise ValueError(f"Invalid function type {type(f)}")
        self.set_value(f)

    def labels(self, *labelvalues):
        if not self._labelnames:
            raise ValueError("No label names")
        with self._lock:
            return self._with_labels(self._labelnames, labelvalues)

    def describe(self):
        with self._lock:
            values = self.render_values()
            if values:
                return self._header() + values


class Gauge(Metric):
    """Gauge metric, to report instantaneous values."""

    _type = "gauge"

    def __init__(
        self,
        name,
        description=None,
        label_names=None,
        registry=REGISTRY,
        _label_values=None,
    ):
        super().__init__(
            name,
            description=description,
            label_names=label_names,
            registry=registry,
            _label_values=_label_values,
        )

    def observe(self, value):
        self.set_value(value)


class Counter(Metric):
    """A Counter tracks counts of events or running totals."""

    _type = "counter"

    def __init__(
        self,
        name,
        description=None,
        label_names=None,
        registry=REGISTRY,
        _label_values=None,
    ):
        super().__init__(
            name,
            description=description,
            label_names=label_names,
            registry=registry,
            _label_values=_label_values,
        )

    def inc(self, amount=1):
        if amount < 0:
            raise ValueError(
                "Counters can only be incremented by non-negative amounts."
            )
        self.inc(amount)


class Histogram(Metric):
    """A Histogram tracks the size and number of events in buckets."""

    DEFAULT_BUCKETS = (
        0.005,
        0.01,
        0.025,
        0.05,
        0.075,
        0.1,
        0.25,
        0.5,
        0.75,
        1.0,
        2.5,
        5.0,
        7.5,
        10.0,
        INF,
    )

    _type = "histogram"

    def __init__(
        self,
        name,
        description=None,
        buckets=DEFAULT_BUCKETS,
        label_names=None,
        registry=REGISTRY,
        _label_values=None,
    ):
        super().__init__(
            name,
            description=description,
            label_names=label_names,
            registry=registry,
            _label_values=_label_values,
        )
        self.buckets = [float(b) for b in sorted(buckets)]
        if self.buckets and self.buckets[-1] != INF:
            self.buckets.append(INF)
        self._bucket_counts = {}
        self._sum = None
        self._count = None

    def _prepare_buckets(self):
        for b in self.buckets:
            self._bucket_counts[b] = self._with_labels(
                ("le",) + self._labelnames, (b,) + self._labelvalues
            )
            self._bucket_counts[b].suffix = "_bucket"
        self._sum = Metric(
            self.name,
            description=self.description,
            label_names=self._labelnames,
            registry=self._registry,
            suffix="_sum",
            _label_values=self._labelvalues,
        )
        self._childs[("__sum",)] = self._sum
        self._count = Metric(
            self.name,
            description=self.description,
            label_names=self._labelnames,
            registry=self._registry,
            suffix="_count",
            _label_values=self._labelvalues,
        )
        self._childs[("__count",)] = self._count

    def labels(self, *labelvalues):
        metric = super().labels(*labelvalues)
        metric.buckets = self.buckets
        return metric

    def observe(self, amount):
        self._raise_if_not_observable()
        with self._lock:
            if self._count is None:
                self._prepare_buckets()
            self._sum.inc(amount)
            self._count.inc()
            for b in self.buckets:
                if amount <= b:
                    self._bucket_counts[b].inc()
