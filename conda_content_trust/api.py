from functools import lru_cache
from glob import glob
import json
from logging import getLogger
from os import makedirs
from os.path import basename, isdir, join, exists
from typing import Optional
import warnings

from conda.base.context import context
from conda.common.url import join_url
from conda.gateways.connection import HTTPError, InsecureRequestWarning
from conda.gateways.connection.session import CondaSession

from .authentication import verify_root, verify_delegation
from .common import load_metadata_from_file, write_metadata_to_file, SignatureError
from .constants import INITIAL_TRUST_ROOT, KEY_MGR_FILE
from .signing import wrap_as_signable


log = getLogger(__name__)


class MetadataSignatureStatus:
    def __init__(self):
        if not isdir(context.av_data_dir):
            log.info("creating directory for artifact verification metadata")
            makedirs(context.av_data_dir)

    @property
    @lru_cache
    def trusted_root(self):
        # TODO: formalize paths for `*.root.json` and `key_mgr.json` on server-side
        trusted = INITIAL_TRUST_ROOT

        # Load current trust root metadata from filesystem
        for path in sorted(glob(join(context.av_data_dir, "[0-9]*.root.json")), reverse=True):
            try:
                int(basename(path).split(".")[0])
            except ValueError:
                # prefix is not an int and is consequently an invalid file, skip to the next
                pass
            else:
                log.info(f"Loading root metadata from {path}.")
                trusted = load_metadata_from_file(path)
                break
        else:
            log.debug(
                f"No root metadata in {context.av_data_dir}. "
                "Using built-in root metadata."
            )

        # Refresh trust root metadata
        while True:
            # TODO: caching mechanism to reduce number of refresh requests
            fname = f"{trusted['signed']['version'] + 1}.root.json"
            path = join(context.av_data_dir, fname)

            # log.info(f"Fetching updated trust root if it exists: {self.channel.base_url}/{fname}")

            try:
                # TODO: support fetching root data with credentials
                untrusted = fetch_channel_signing_data(
                    context.signing_metadata_url_base,
                    fname,
                )

                verify_root(trusted, untrusted)
            except HTTPError as err:
                # HTTP 404 implies no updated root.json is available, which is
                # not really an "error" and does not need to be logged.
                if err.response.status_code != 404:
                    log.error(err)
                break
            except Exception as err:
                # TODO: more error handling
                log.error(err)
                break
            else:
                # New trust root metadata checks out
                trusted = untrusted
                write_metadata_to_file(trusted, path)

        return trusted

    @property
    @lru_cache
    def key_mgr(self):
        trusted = None

        # Refresh key manager metadata
        fname = KEY_MGR_FILE
        path = join(context.av_data_dir, fname)

        # log.info(f"Fetching updated key manager if it exists: {self.channel.base_url}/{fname}")

        try:
            untrusted = fetch_channel_signing_data(
                context.signing_metadata_url_base,
                KEY_MGR_FILE,
            )

            verify_delegation("key_mgr", untrusted, self.trusted_root)
        except (ConnectionError, HTTPError) as err:
            log.warn(err)
        except Exception as err:
            # TODO: more error handling
            raise
            log.error(err)
        else:
            # New key manager metadata checks out
            trusted = untrusted
            write_metadata_to_file(trusted, path)

        # If key_mgr is unavailable from server, fall back to copy on disk
        if not trusted and exists(path):
            trusted = load_metadata_from_file(path)

        return trusted

    def __call__(self, record) -> Optional[str]:
        # safety_checks must be enabled
        # must have signatures to validate
        if not context.extra_safety_checks or not getattr(record, "signatures", None):
            return None

        try:
            verify_delegation('pkg_mgr', wrap_as_signable(record.info, record.signatures), self.key_mgr)
        except SignatureError:
            log.warn(f"invalid signature for {record.fn}")
            return "(WARNING: metadata signature verification failed)"
        else:
            return "(INFO: package metadata is signed by Anaconda and trusted)"


# singleton for caching
metadata_signature_status = MetadataSignatureStatus()


def fetch_channel_signing_data(signing_data_url, filename, etag=None, mod_stamp=None):
    if not context.ssl_verify:
        warnings.simplefilter('ignore', InsecureRequestWarning)

    session = CondaSession()

    headers = {
        'Accept-Encoding': 'gzip, deflate, compress, identity',
        'Content-Type': 'application/json',
    }
    if etag:
        headers["If-None-Match"] = etag
    if mod_stamp:
        headers["If-Modified-Since"] = mod_stamp

    try:
        # The `auth` argument below looks a bit weird, but passing `None` seems
        # insufficient for suppressing modifying the URL to add an Anaconda
        # server token; for whatever reason, we must pass an actual callable in
        # order to suppress the HTTP auth behavior configured in the session.
        #
        # TODO: Figure how to handle authn for obtaining trust metadata,
        # independently of the authn used to access package repositories.
        resp = session.get(
            join_url(signing_data_url, filename),
            headers=headers,
            proxies=session.proxies,
            auth=lambda r: r,
            timeout=(context.remote_connect_timeout_secs, context.remote_read_timeout_secs),
        )

        resp.raise_for_status()
    except:
        # TODO: more sensible error handling
        raise

    # In certain cases (e.g., using `-c` access anaconda.org channels), the
    # `CondaSession.get()` retry logic combined with the remote server's
    # behavior can result in non-JSON content being returned.  Parse returned
    # content here (rather than directly in the return statement) so callers of
    # this function only have to worry about a ValueError being raised.
    try:
        str_data = json.loads(resp.content)
    except json.decoder.JSONDecodeError as err:  # noqa
        raise ValueError(f"Invalid JSON returned from {signing_data_url}/{filename}") from err

    # TODO: additional loading and error handling improvements?

    return str_data
