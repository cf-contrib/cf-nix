import "@typespec/http";
import "@typespec/openapi";
import "@typespec/openapi3";
import "@typespec/versioning";

using Http;
using OpenAPI;
using Versioning;

/**
 * A Nix binary cache on Cloudflare Workers and R2. Reads are public. Uploads
 * need an OIDC token from an issuer the Worker trusts, as the password of
 * HTTP Basic credentials.
 *
 * Errors are JSON, `{ error, message }`. A request that doesn't fit
 * this document (a body over the size limit, the wrong content type) is
 * rejected before it reaches the Worker, as `application/problem+json`.
 */
@service(#{ title: "cf-nix-cache" })
@info(#{ license: #{ name: "MIT" } })
@tagMetadata("CacheService", #{ description: "The Nix binary cache protocol." })
@versioned(Versions)
namespace Nix.Cache.v1;

enum Versions {
  v1,
}

/**
 * An OIDC token from an issuer the Worker trusts, as the password. The
 * username isn't read.
 */
model basic is BasicAuth;

/** An error, `{ error, message }`. */
model Error {
  error: ErrorCode;

  /** What went wrong. Nix prints it when an upload fails. */
  message: string;
}

enum ErrorCode {
  bad_request,
  unauthorized,
  forbidden,
  not_found,
  misconfigured,
  internal_error,
  upstream_error,
}

// A response with no body, described by `Description`.
@doc(Description)
model Empty<Code, Description extends valueof string> {
  @statusCode _: Code;
}

/** The narinfo or request is invalid. */
@error
model BadRequest {
  @statusCode _: 400;
  @body body: Error;
}

/**
 * Missing or invalid credentials: no token, a token from an issuer the
 * Worker doesn't trust, or one for another audience or expired.
 */
@error
model Unauthorized {
  @statusCode _: 401;
  @body body: Error;
}

/** A valid token that no claim set for its issuer allows. */
@error
model Forbidden {
  @statusCode _: 403;
  @body body: Error;
}

/** No such object. */
@error
model NotFound {
  @statusCode _: 404;
  @body body: Error;
}

/**
 * The auth config, the bindings or the signing key are invalid
 * (`misconfigured`), or a stored object is unreadable (`internal_error`).
 * Details go only to the logs.
 */
@error
model InternalServerError {
  @statusCode _: 500;
  @body body: Error;
}

/** The token's issuer, its discovery document or its keys, couldn't be reached. */
@error
model BadGateway {
  @statusCode _: 502;
  @body body: Error;
}

/** What an upload can fail with. */
alias UploadErrors =
  | Unauthorized
  | Forbidden
  | InternalServerError
  | BadGateway;

@tag("CacheService")
interface CacheService {
  /**
   * The store directory, priority and mass-query support, in the format Nix reads.
   *
   * @returns The cache's metadata.
   */
  @summary("Cache metadata")
  @operationId("getNixCacheInfo")
  @route("/nix-cache-info")
  @get
  getNixCacheInfo(): {
    @header contentType: "text/x-nix-cache-info";
    @body body: string;
  };

  /**
   * Takes a newline-separated list of store path hashes and returns the
   * ones that are in the cache, so a client can check many at once.
   *
   * @returns The cached subset of the hashes, one per line.
   */
  @summary("Mass query")
  @operationId("postMassQuery")
  @route("/")
  @post
  postMassQuery(@header contentType: "text/plain", @body body: string):
    | {
        @header contentType: "text/plain";
        @body body: string;
      }
    | InternalServerError;

  /** Lets an uploader skip store paths the cache already has. */
  @summary("Check for a narinfo")
  @operationId("headNarInfo")
  @route("/{hash}.narinfo")
  @head
  headNarInfo(
    /** The hash part of a store path. */
    @path hash: string,
  ):
    | Empty<200, "The narinfo exists.">
    | Empty<404, "No such narinfo.">
    | Empty<500, "The bucket couldn't be read.">;

  /**
   * The narinfo for a store path, as it was uploaded, with a `Sig:` line if
   * the Worker signed it.
   *
   * @returns The narinfo.
   */
  @summary("Get a narinfo")
  @operationId("getNarInfo")
  @route("/{hash}.narinfo")
  @get
  getNarInfo(
    /** The hash part of a store path. */
    @path hash: string,
  ):
    | {
        @header contentType: "text/x-nix-narinfo";
        @body body: string;
      }
    | NotFound
    | InternalServerError;

  /**
   * Parses and validates the narinfo, and requires its `StorePath` to match
   * the hash. It is stored as sent. If it has no `Sig:`, the Worker signs it
   * with `CF_NIX_CACHE_API_SECRET`, and rejects it when no key is set.
   */
  @summary("Upload a narinfo")
  @operationId("putNarInfo")
  @route("/{hash}.narinfo")
  @useAuth(basic)
  @put
  putNarInfo(
    /** The hash part of a store path. */
    @path hash: string,

    @header contentType: "text/x-nix-narinfo",
    @body body: string,
  ): Empty<200, "The narinfo was stored."> | BadRequest | UploadErrors;

  /** Lets an uploader skip NARs the cache already has. */
  @summary("Check for a NAR")
  @operationId("headNar")
  @route("/nar/{hash}.nar")
  @head
  headNar(
    /** The NAR's file hash, from the narinfo's `URL`. */
    @path hash: string,
  ):
    | Empty<200, "The NAR exists.">
    | Empty<404, "No such NAR.">
    | Empty<500, "The bucket couldn't be read.">;

  /**
   * The NAR archive a narinfo's `URL` points at.
   *
   * @returns The NAR.
   */
  @summary("Get a NAR")
  @operationId("getNar")
  @route("/nar/{hash}.nar")
  @get
  getNar(
    /** The NAR's file hash, from the narinfo's `URL`. */
    @path hash: string,
  ):
    | {
        @header contentType: "application/x-nix-archive";
        @body body: bytes;
      }
    | NotFound
    | InternalServerError;

  /**
   * Stores a NAR archive. Compressed NARs aren't supported: upload with
   * `?compression=none`.
   */
  @summary("Upload a NAR")
  @operationId("putNar")
  @route("/nar/{hash}.nar")
  @useAuth(basic)
  @put
  putNar(
    /** The NAR's file hash, from the narinfo's `URL`. */
    @path hash: string,

    // What Nix sends; it's served back as application/x-nix-archive.
    @header contentType: "application/x-nix-nar",

    @body body: bytes,
  ): Empty<200, "The NAR was stored."> | UploadErrors;
}
