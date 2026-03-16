from io import StringIO

from jsonlines import jsonlines
from rest_framework.renderers import BaseRenderer


class JSONLRenderer(BaseRenderer):
    """
    Renderer which serializes to JSONL. Based on rest_framework.renderers.JSONRenderer
    """
    media_type = 'application/jsonl'
    format = 'jsonl'

    # We don't set a charset because JSON is a binary encoding,
    # that can be encoded as utf-8, utf-16 or utf-32.
    # See: https://www.ietf.org/rfc/rfc4627.txt
    # Also: http://lucumr.pocoo.org/2013/7/19/application-mimetypes-and-encodings/
    charset = None

    def render(self, data, accepted_media_type=None, renderer_context=None):
        """
        Render `data` into JSONL, returning a bytestring.
        """
        if data is None:
            return b''

        io = StringIO()
        with jsonlines.Writer(io) as jsonl_writer:
            if isinstance(data, list):
                jsonl_writer.write_all(data)
            else:
                jsonl_writer.write(data)

        ret = io.getvalue()

        # We always fully escape \u2028 and \u2029 to ensure we output JSON
        # that is a strict javascript subset.
        # See: https://gist.github.com/damncabbage/623b879af56f850a6ddc
        ret = ret.replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
        return ret.encode()
