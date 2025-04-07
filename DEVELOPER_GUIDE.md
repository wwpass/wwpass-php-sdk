# Developer Instructions for Managing GitHub and Packagist Integration 
When working on the WWPass GitHub repository connected to Packagist, follow these guidelines to ensure updates are properly reflected in the Composer package.

## Updating the Composer Package

### Key Principle
- **Tags Are Immutable**:  Once a tag is created and pushed, it represents a fixed point in the project’s history. Modifying the repository without changing the tag will not update the package on Packagist.

### Procedure for Updating Scripts

1. **Commit Your Changes**
    - Ensure all your changes are committed. Use clear and descriptive commit messages to outline the modifications made. 
```bash
git add .
git commit -m "Describe the changes made"
```
2. **Create a New Tag** 
    - Each change that affects the main scripts should be followed by creating a new tag. This helps in tracking changes and maintaining version integrity. 
```bash
    git tag X.Y.Z  # Replace X.Y.Z with the new version number
```
- Follow [Semantic Versioning](https://semver.org) for version numbers: 
    - **MAJOR** version when you make incompatible API changes.
    - **MINOR** version when you add functionality in a backward-compatible manner.
    - **PATCH** version when you make backward-compatible bug fixes.

3. **Push the Tag to GitHub**
    - Push your changes and the new tag to the remote repository.
```bash
    git push origin master  # Ensure 'master' is your working branch
    git push origin X.Y.Z  # Push the new tag
```
4. **Verify Packagist Update**
    - Packagist will automatically detect the new tag and update the package details.

### Important Notes
- **Do Not Reuse Tags:** Always create a new tag for any changes requiring updates in the Composer package.
- **Communication:** Notify team members about the changes and the new version. 