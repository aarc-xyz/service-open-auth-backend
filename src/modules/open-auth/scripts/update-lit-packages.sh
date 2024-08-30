#!/bin/bash

# Pass version in first argument or use latest tag
VERSION=${1:-latest}

PACKAGES=(
  "@lit-protocol/auth-helpers"
  "@lit-protocol/contracts-sdk"
  "@lit-protocol/lit-auth-client"
  "@lit-protocol/lit-node-client"
  "@lit-protocol/pkp-ethers"
)

echo "Updating all Lit packages to version $VERSION"

for PACKAGE in "${PACKAGES[@]}"; do
  echo "Updating $PACKAGE to $VERSION"
  npm install $PACKAGE@$VERSION
done
