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

    def parse(self, stream, media_type=None, parser_context=None):
        request = parser_context['request']
        filename = self.get_filename(stream, media_type, parser_context)
        if not filename:
            raise ParseError(self.errors['no_filename'])

        try:
            content_length = int(request.META.get('HTTP_CONTENT_LENGTH',
                                                  request.META.get('CONTENT_LENGTH', 0)))
        except (ValueError, TypeError):
            content_length = None

        file_meta = self.get_file_meta(request.META)
        return DataAndFiles({}, {'file': FilerFile(
            file_meta['filename'], file_meta['filepath'], stream, content_length)})

    def get_file_meta(self, META):
        """
        Detects the uploaded file name. First searches a 'filename' url kwarg.
        Then tries to parse Content-Disposition header.
        """
        with contextlib.suppress(AttributeError, KeyError, ValueError):
            _, params = parse_header_parameters(META['HTTP_CONTENT_DISPOSITION'])
            return params
