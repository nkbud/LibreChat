# Release Process for nkbud/LibreChat

This document describes the release and deployment process for the nkbud/LibreChat fork.

## Overview

This fork maintains a simplified CI/CD infrastructure focused on essential workflows:
- Backend unit tests
- Frontend unit tests  
- Docker image builds to GitHub Container Registry (GHCR)

All container images are published to the `ghcr.io/nkbud/` namespace.

## Active Workflows

### 1. Backend Unit Tests (`backend-review.yml`)

**Trigger:** Pull requests to `main`, `dev`, or `release/*` branches that modify `api/**` or `packages/**`

**Purpose:** Runs backend unit tests to ensure code quality

**What it does:**
- Runs unit tests for API
- Runs unit tests for librechat-data-provider package
- Runs unit tests for @librechat/data-schemas package
- Runs unit tests for @librechat/api package
- Checks for circular dependencies

### 2. Frontend Unit Tests (`frontend-review.yml`)

**Trigger:** Pull requests to `main`, `dev`, or `release/*` branches that modify `client/**` or `packages/data-provider/**`

**Purpose:** Runs frontend unit tests on both Ubuntu and Windows

**What it does:**
- Builds the client
- Runs client unit tests on Ubuntu
- Runs client unit tests on Windows
- Ensures cross-platform compatibility

### 3. Docker Image Builds (`tag-images.yml`)

**Trigger:** When a new tag is pushed to the repository

**Purpose:** Automatically builds and publishes Docker images for official releases

**What it does:**
- Builds both `librechat` and `librechat-api` images
- Publishes to GitHub Container Registry (GHCR) at `ghcr.io/nkbud/`
- Creates multi-platform images (linux/amd64, linux/arm64)
- Tags images with both the version tag and `latest`

**Example:**
```bash
# Create and push a new release tag
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

This will automatically build and publish:
- `ghcr.io/nkbud/librechat:v1.0.0`
- `ghcr.io/nkbud/librechat:latest`
- `ghcr.io/nkbud/librechat-api:v1.0.0`
- `ghcr.io/nkbud/librechat-api:latest`

## Container Registry

### GitHub Container Registry (GHCR)

All images are automatically published to GHCR under the `nkbud` namespace:
- Registry: `ghcr.io`
- Namespace: `nkbud`
- Authentication: Automatic via `GITHUB_TOKEN`

**Available images:**
- `ghcr.io/nkbud/librechat` - Production image (Dockerfile)
- `ghcr.io/nkbud/librechat-api` - API-only image (Dockerfile.multi)

## Creating a New Release

### Step 1: Prepare the Release

1. Ensure all desired changes are merged to `main`
2. Update `CHANGELOG.md` with release notes
3. Commit the changelog update

### Step 2: Create and Push the Tag

```bash
# Fetch latest changes
git checkout main
git pull origin main

# Create an annotated tag
git tag -a v1.2.3 -m "Release v1.2.3"

# Push the tag to GitHub
git push origin v1.2.3
```

### Step 3: Monitor the Build

1. Go to Actions tab in GitHub: https://github.com/nkbud/LibreChat/actions
2. Watch the "Docker Images Build on Tag" workflow
3. Verify successful completion

### Step 4: Verify Published Images

Check that images are available:
```bash
# Pull the new image
docker pull ghcr.io/nkbud/librechat:v1.2.3

# Verify the tag
docker images | grep nkbud/librechat
```

### Step 5: Create GitHub Release (Optional)

1. Go to: https://github.com/nkbud/LibreChat/releases/new
2. Select the tag you just created
3. Add release notes (can copy from CHANGELOG.md)
4. Publish the release

## Using Published Images

### With Docker

```bash
# Pull and run the latest release
docker pull ghcr.io/nkbud/librechat:latest
docker run -d -p 3080:3080 ghcr.io/nkbud/librechat:latest
```

### With Docker Compose

Update your `docker-compose.yml`:

```yaml
services:
  api:
    image: ghcr.io/nkbud/librechat:latest
    # ... other configuration
```

Then:
```bash
docker-compose pull
docker-compose up -d
```

### Using Specific Versions

```bash
# Use a specific version
docker pull ghcr.io/nkbud/librechat:v1.2.3

# Or in docker-compose.yml
services:
  api:
    image: ghcr.io/nkbud/librechat:v1.2.3
```

## Rollback Process

If a release has issues:

1. **Quick rollback** - Point to a previous tag:
   ```bash
   docker pull ghcr.io/nkbud/librechat:v1.2.2
   ```

2. **Delete bad tag** (if needed):
   ```bash
   # Delete local tag
   git tag -d v1.2.3
   
   # Delete remote tag
   git push origin :refs/tags/v1.2.3
   ```

## Troubleshooting

### Workflow Not Triggering

- Ensure you pushed the tag: `git push origin <tagname>`
- Check if workflows are enabled in repository settings
- Verify repository permissions for GitHub Actions

### Build Failures

- Check the Actions logs for specific errors
- Common issues:
  - Missing or invalid `.env.example` file
  - Docker build context errors
  - Platform-specific build issues

### Image Not Found

- Verify the image was published: Check Packages tab in GitHub
- Ensure you're using the correct image name: `ghcr.io/nkbud/librechat`
- Check if you have permission to pull the image (for private repos)

### Permission Denied When Pulling

For private repositories, authenticate with GitHub:
```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
```

## Repository Secrets Required

### Required for GHCR Publishing
- `GITHUB_TOKEN` - Automatically provided by GitHub Actions

### Required for Unit Tests
- `MONGO_URI` - MongoDB connection string for backend tests
- `OPENAI_API_KEY` - OpenAI API key for backend tests
- `JWT_SECRET` - JWT secret for backend tests
- `CREDS_KEY` - Credentials encryption key
- `CREDS_IV` - Credentials encryption IV
- `BAN_VIOLATIONS` - Ban violations setting
- `BAN_DURATION` - Ban duration setting
- `BAN_INTERVAL` - Ban interval setting

## Differences from Upstream

This fork's workflow setup differs from DannyAvila/LibreChat:

1. **Simplified workflows** - Only essential CI/CD workflows are enabled
2. **GHCR only** - Container images published only to `ghcr.io/nkbud/`, not Docker Hub
3. **No dev/staging workflows** - Removed dev branch image builds and deployment workflows
4. **No publishing workflows** - Removed NPM package publishing workflows
5. **No additional checks** - Removed ESLint CI, accessibility linting, i18n checks, etc.

## Keeping Up with Upstream

To incorporate updates from the upstream repository:

```bash
# Add upstream remote (one time)
git remote add upstream https://github.com/danny-avila/LibreChat.git

# Fetch upstream changes
git fetch upstream

# Merge upstream main into your main
git checkout main
git merge upstream/main

# Resolve any conflicts, then push
git push origin main
```

After merging upstream changes, consider creating a new release to make them available in your published images.
