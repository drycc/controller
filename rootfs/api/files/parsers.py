import contextlib
from django.utils.http import parse_header_parameters
from django.core.files.uploadedfile import UploadedFile
from rest_framework.exceptions import ParseError
from rest_framework.parsers import FileUploadParser, DataAndFiles


class FilerFile(UploadedFile):

    def __init__(self, filename, filepath, input_data, content_length):
        self.filename = filename
        self.filepath = filepath
        super().__init__(input_data, name=filename, size=content_length)


class FilerUploadParser(FileUploadParser):
    """
    Filer upload parser.
    """
    media_type = 'filer/octet-stream'

    errors = {
        "no_filepath": (
            "Missing filepath. Request should include a Content-Disposition "
            "header with a filepath parameter."
        ),
    }
    errors.update(FileUploadParser.errors)

    def parse(self, stream, media_type=None, parser_context=None):
        request = parser_context['request']
        filename = self.get_filename(stream, media_type, parser_context)
        if not filename:
            raise ParseError(self.errors['no_filename'])
        filepath = self.get_filepath(stream, media_type, parser_context)
        if not filepath:
            raise ParseError(self.errors['no_filepath'])
        try:
            content_length = int(request.META.get('HTTP_CONTENT_LENGTH',
                                                  request.META.get('CONTENT_LENGTH', 0)))
        except (ValueError, TypeError):
            content_length = None
        return DataAndFiles({}, {'file': FilerFile(filename, filepath, stream, content_length)})

    def get_filepath(self, stream, media_type, parser_context):
        """
        Detects the uploaded file name. First searches a 'filepath' url kwarg.
        Then tries to parse Content-Disposition header.
        """
        with contextlib.suppress(KeyError):
            return parser_context['kwargs']['filepath']

        with contextlib.suppress(AttributeError, KeyError, ValueError):
            meta = parser_context['request'].META
            _, params = parse_header_parameters(meta['HTTP_CONTENT_DISPOSITION'])
            if 'filepath*' in params:
                return params['filepath*']
            return params['filepath']
