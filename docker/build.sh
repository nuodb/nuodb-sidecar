#!/bin/sh

fail() {
    printf "$1\n" >&2
    exit 1
}

set -e

# Make sure we are in root of Git repository
cd "$(dirname "$0")/.."

# Get commit SHA
COMMIT="$(git rev-parse --short HEAD)"

# Add "~" to commit SHA if there are uncommitted changes
GIT_STATUS="$(git status --porcelain)"
[ "$GIT_STATUS" = "" ] || COMMIT="${COMMIT}~"

# Build the image and label it with commit SHA
: ${IMG_REPO:="nuodb/nuodb-sidecar"}
: ${IMG_TAG:="latest"}

docker build -f ./docker/Dockerfile . --tag "$IMG_REPO:$IMG_TAG" --label org.opencontainers.image.revision="$COMMIT"

# Also tag image with commit SHA if there are no uncommitted changes
if [ "$GIT_STATUS" = "" ]; then
    docker tag "$IMG_REPO:$IMG_TAG" "$IMG_REPO:sha-$COMMIT"
fi

# Use PUSH_REPO to specify remote Docker repo to publish to
if [ "$PUSH_REPO" != "" ] && [ "$(read -p "Push image to \"$PUSH_REPO\" with tag \"$IMG_TAG\" (yes/no)? " && echo "$REPLY")" = "yes" ]; then
    # Make sure there are no uncommitted changes
    [ "$GIT_STATUS" = "" ] || fail "Cannot push image with uncommitted changes:\n$GIT_STATUS"

    docker tag "$IMG_REPO:$IMG_TAG" "$PUSH_REPO:$IMG_TAG"
    docker push "$PUSH_REPO:$IMG_TAG"

    # Also tag image with commit SHA
    docker tag "$IMG_REPO:$IMG_TAG" "$PUSH_REPO:sha-$COMMIT"
    docker push "$PUSH_REPO:sha-$COMMIT"
fi
