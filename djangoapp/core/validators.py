from django.core.exceptions import ValidationError
import os, zipfile

ALLOWED_PDF_EXT = {".pdf"}

def validate_pdf_magic(file_obj):
    pos = file_obj.tell()
    file_obj.seek(0)
    head = file_obj.read(5)
    file_obj.seek(pos)
    if head != b'%PDF-':
        raise ValidationError('Arquivo inválido (não é PDF).')

def validate_file_max_size(file_obj, max_bytes: int = 10 * 1024 * 1024):
    size = getattr(file_obj, 'size', None)
    if size is not None and size > max_bytes:
        raise ValidationError(f'Arquivo excede {max_bytes // (1024*1024)}MB.')

def validate_safe_filename(file_field, *, allow_ext = ALLOWED_PDF_EXT):
    name = getattr(file_field, 'name', '') or ''
    _, ext = os.path.splitext(name.lower())
    if ext not in allow_ext:
        raise ValidationError('Extensão não permitida.')
    if any(c in name for c in ('\\', '/', '\x00', '..')):
        raise ValidationError('Nome de arquivo inválido.')

def validate_zip_depth(file_obj, *, max_members: int = 200, max_total_uncompressed: int = 100*1024*1024):
    pos = file_obj.tell()
    try:
        file_obj.seek(0)
        with zipfile.ZipFile(file_obj) as z:
            infos = z.infolist()
            if len(infos) > max_members:
                raise ValidationError('ZIP muito grande.')
            total = 0
            for i in infos:
                total += i.file_size
                if total > max_total_uncompressed:
                    raise ValidationError('ZIP com expansão excessiva.')
    except zipfile.BadZipFile:
        raise ValidationError('ZIP inválido.')
    finally:
        file_obj.seek(pos)
