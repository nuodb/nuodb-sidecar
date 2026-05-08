import http


class HttpError(RuntimeError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


class UserError(HttpError):
    def __init__(self, message):
        super().__init__(http.HTTPStatus.BAD_REQUEST, message)
