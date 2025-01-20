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

# Extract the first image tag
MAIN_TAG="$(echo "$IMG_TAG" | awk '{print $1}')"

docker build -f ./docker/Dockerfile . --tag "$IMG_REPO:$MAIN_TAG" --label org.opencontainers.image.revision="$COMMIT"

# Also tag the image with other tags if specified
for tag in $IMG_TAG; do
    docker tag "$IMG_REPO:$MAIN_TAG" "$IMG_REPO:$tag"
done

# Also tag image with commit SHA if there are no uncommitted changes
if [ "$GIT_STATUS" = "" ]; then
    docker tag "$IMG_REPO:$MAIN_TAG" "$IMG_REPO:sha-$COMMIT"
fi

# Use PUSH_REPO to specify remote Docker repo to publish to
if [ "$PUSH_REPO" != "" ] && [ "$(read -p "Push image to \"$PUSH_REPO\" with tag \"$MAIN_TAG\" (yes/no)? " REPLY && echo "$REPLY")" = "yes" ]; then
    # Make sure there are no uncommitted changes
    [ "$GIT_STATUS" = "" ] || fail "Cannot push image with uncommitted changes:\n$GIT_STATUS"

    # Tag the image with other tags if specified
    for tag in $IMG_TAG; do
        docker tag "$IMG_REPO:$MAIN_TAG" "$PUSH_REPO:$tag"
        docker push "$PUSH_REPO:$tag"
    done

    # Also tag image with commit SHA
    docker tag "$IMG_REPO:$MAIN_TAG" "$PUSH_REPO:sha-$COMMIT"
    docker push "$PUSH_REPO:sha-$COMMIT"
fi
