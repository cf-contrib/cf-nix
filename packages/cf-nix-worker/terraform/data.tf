data "github_release" "worker" {
  owner       = "cf-contrib"
  repository  = "cf-nix-cache"
  retrieve_by = "latest"
}

locals {
  github_release_asset_urls = {
    for item in data.github_release.worker.assets : item.name => item.browser_download_url
  }
}

data "http" "index_js" {
  url = local.github_release_asset_urls["index.js"]
}

data "http" "index_wasm" {
  url = local.github_release_asset_urls["index_bg.wasm"]
}
