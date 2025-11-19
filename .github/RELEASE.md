# Release Process for nkbud/LibreChat

This document describes the release and deployment process for the nkbud/LibreChat fork.

## Overview

This fork maintains its own release and deployment infrastructure, separate from the upstream DannyAvila/LibreChat repository. All releases, tags, and container images are published under the nkbud namespace.

## Release Workflows

### 1. Tag-based Image Builds (`tag-images.yml`)

**Trigger:** When a new tag is pushed to the repository

**Purpose:** Automatically builds and publishes Docker images for official releases

**What it does:**
- Builds both `librechat` and `librechat-api` images
- Publishes to GitHub Container Registry (GHCR) at `ghcr.io/nkbud/`
- Publishes to Docker Hub (if credentials are configured)
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

### 2. Main Branch Image Builds (`main-image-workflow.yml`)

**Trigger:** Manual dispatch via GitHub Actions UI

**Purpose:** Rebuild images based on the latest tag

**What it does:**
- Fetches the latest git tag
- Builds and publishes images with that tag
- Updates the `latest` tag
- Useful for rebuilding without creating a new tag

### 3. Development Branch Images (`dev-images.yml`)

**Trigger:** Pushes to `main` branch (automatically), or manual dispatch

**Purpose:** Creates development/preview images for testing

**What it does:**
- Builds `librechat-dev` and `librechat-dev-api` images
- Tags with commit SHA and `latest`
- Published to `ghcr.io/nkbud/`

**Example images:**
- `ghcr.io/nkbud/librechat-dev:abc123` (where abc123 is the commit SHA)
- `ghcr.io/nkbud/librechat-dev:latest`

### 4. Dev Branch Images (`dev-branch-images.yml`)

**Trigger:** Pushes to `dev` branch

**Purpose:** Creates images for the dev branch specifically

**What it does:**
- Similar to dev-images.yml but for the `dev` branch
- Builds `lc-dev` and `lc-dev-api` images

## Container Registries

### GitHub Container Registry (GHCR)

All images are automatically published to GHCR under the `nkbud` namespace:
- Registry: `ghcr.io`
- Namespace: `nkbud`
- Authentication: Automatic via `GITHUB_TOKEN`

**Available images:**
- `ghcr.io/nkbud/librechat` - Production image (Dockerfile)
- `ghcr.io/nkbud/librechat-api` - API-only image (Dockerfile.multi)
- `ghcr.io/nkbud/librechat-dev` - Development image from main branch
- `ghcr.io/nkbud/librechat-dev-api` - Development API image from main branch
- `ghcr.io/nkbud/lc-dev` - Development image from dev branch
- `ghcr.io/nkbud/lc-dev-api` - Development API image from dev branch

### Docker Hub (Optional)

If Docker Hub credentials are configured as repository secrets, images will also be published to Docker Hub:
- Required secrets: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`
- Published to: `$DOCKERHUB_USERNAME/librechat`, etc.

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

3. **Rebuild previous version** as latest:
   - Go to Actions > "Docker Compose Build Latest Main Image Tag"
   - Click "Run workflow"
   - This will rebuild the latest git tag and publish as `latest`

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

For full functionality, configure these secrets in repository settings:

### Required for GHCR Publishing
- `GITHUB_TOKEN` - Automatically provided by GitHub Actions

### Optional for Docker Hub Publishing
- `DOCKERHUB_USERNAME` - Your Docker Hub username
- `DOCKERHUB_TOKEN` - Docker Hub access token

### Optional for Other Features
- `AXE_LINTER_API_KEY` - For accessibility linting
- `LOCIZE_API_KEY`, `LOCIZE_PROJECT_ID` - For translation management
- `AZURE_CREDENTIALS` - For Azure deployments
- `DO_SSH_PRIVATE_KEY`, `DO_KNOWN_HOSTS`, `DO_HOST`, `DO_USER` - For DigitalOcean deployments

## Differences from Upstream

This fork's release process differs from DannyAvila/LibreChat in the following ways:

1. **All workflows reference `nkbud/LibreChat`** instead of `danny-avila/LibreChat`
2. **Container images are published to `ghcr.io/nkbud/`** instead of `ghcr.io/danny-avila/`
3. **Pull request reviewers default to `nkbud`** instead of `danny-avila`
4. **Independent release versioning** - This fork maintains its own version numbering
5. **Deployment workflows** are configured for nkbud's infrastructure

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
