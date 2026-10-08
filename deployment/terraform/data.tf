# The release is only downloaded when no local bundle_dir is given.
data "github_release" "this" {
  count = var.bundle_dir == null ? 1 : 0

  owner       = "cf-contrib"
  repository  = "cloudflare-nix"
  retrieve_by = var.release_tag == "latest" ? "latest" : "tag"
  release_tag = var.release_tag == "latest" ? null : var.release_tag
}

locals {
  release_assets = var.bundle_dir != null ? {} : {
    for asset in data.github_release.this[0].assets : asset.name => asset.browser_download_url
  }
}

data "http" "index_js" {
  count = var.bundle_dir == null ? 1 : 0

  url = local.release_assets["index.js"]
}

data "http" "index_wasm" {
  count = var.bundle_dir == null ? 1 : 0

  url = local.release_assets["index_bg.wasm"]
}

locals {
  index_js_base64 = (var.bundle_dir != null
    ? filebase64("${var.bundle_dir}/index.js")
    : base64encode(data.http.index_js[0].response_body)
  )
  index_wasm_base64 = (var.bundle_dir != null
    ? filebase64("${var.bundle_dir}/index_bg.wasm")
    : data.http.index_wasm[0].response_body_base64
  )
}
