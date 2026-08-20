import os
from pathlib import Path
import zipfile
from uuid import uuid4
from werkzeug.utils import secure_filename


def validate_upload(file):
    if file is None or not getattr(file, 'filename', None):
        raise ValueError('No file was uploaded.')

    filename = secure_filename(file.filename)
    if not filename:
        raise ValueError('Invalid file name.')

    ext = os.path.splitext(filename)[1].lower()
    allowed = {'.pdf', '.png', '.jpg', '.jpeg', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.txt'}
    if ext not in allowed:
        raise ValueError('File type is not allowed.')

    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size <= 0 or size > 16 * 1024 * 1024:
        raise ValueError('File exceeds the 16MB upload limit.')

    sample = file.read(8192)
    file.seek(0)

    if ext == '.pdf' and not sample.startswith(b'%PDF'):
        raise ValueError('PDF content is invalid.')
    if ext in {'.png'} and not sample.startswith(b'\x89PNG\r\n\x1a\n'):
        raise ValueError('PNG content is invalid.')
    if ext in {'.jpg', '.jpeg'} and sample[:2] not in {b'\xff\xd8', b'\xFF\xD8'}:
        raise ValueError('JPEG content is invalid.')
    if ext in {'.docx', '.xlsx'}:
        try:
            if not zipfile.is_zipfile(file):
                raise ValueError('Archive content is invalid.')
        finally:
            file.seek(0)
    if ext in {'.csv', '.txt'} and b'\x00' in sample:
        raise ValueError('Text file content is invalid.')

    return filename


def validate_video_upload(file):
    if file is None or not getattr(file, 'filename', None):
        raise ValueError('No video was uploaded.')

    filename = secure_filename(file.filename)
    if not filename:
        raise ValueError('Invalid file name.')

    ext = os.path.splitext(filename)[1].lower()
    allowed = {'.mp4', '.mov', '.m4v', '.webm', '.avi', '.mkv'}
    if ext not in allowed:
        raise ValueError('Video file type is not allowed.')

    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size <= 0 or size > 250 * 1024 * 1024:
        raise ValueError('Video exceeds the 250MB upload limit.')

    return filename


class StorageService:
    def __init__(self, app=None):
        self.app = app

    @property
    def backend(self):
        if self.app is None:
            return os.getenv('STORAGE_BACKEND', 'local')
        return self.app.config.get('STORAGE_BACKEND', 'local')

    @property
    def upload_root(self):
        if self.app is None:
            configured = os.getenv('UPLOAD_FOLDER', str(Path(__file__).resolve().parent.parent / 'instance' / 'uploads'))
        else:
            configured = self.app.config.get('UPLOAD_FOLDER', str(Path(__file__).resolve().parent.parent / 'instance' / 'uploads'))

        if not os.path.isabs(configured):
            configured = str((Path(__file__).resolve().parent.parent / configured).resolve())
        return configured

    @property
    def bucket_name(self):
        if self.app is None:
            return os.getenv('STORAGE_BUCKET', 'invaryant-local')
        return self.app.config.get('STORAGE_BUCKET', 'invaryant-local')

    def save(self, file, filename):
        if self.backend == 's3':
            return self._save_to_s3(file, filename)
        return self._save_to_local(file, filename)

    def _save_to_local(self, file, filename):
        target_dir = Path(self.upload_root)
        target_dir.mkdir(parents=True, exist_ok=True)
        safe_name = secure_filename(filename)
        suffix = Path(safe_name).suffix.lower()
        target_path = target_dir / f"{uuid4().hex}{suffix}"
        file.save(str(target_path))
        return str(target_path)

    def _save_to_s3(self, file, filename):
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError('boto3 is required for S3 storage support.') from exc

        endpoint_url = self.app.config.get('S3_ENDPOINT_URL') if self.app else os.getenv('S3_ENDPOINT_URL')
        region = self.app.config.get('S3_REGION', 'us-east-1') if self.app else os.getenv('S3_REGION', 'us-east-1')
        access_key = self.app.config.get('S3_ACCESS_KEY_ID') if self.app else os.getenv('S3_ACCESS_KEY_ID')
        secret_key = self.app.config.get('S3_SECRET_ACCESS_KEY') if self.app else os.getenv('S3_SECRET_ACCESS_KEY')

        if hasattr(file, 'seek'):
            file.seek(0)

        client = boto3.client(
            's3',
            endpoint_url=endpoint_url,
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

        key = f"uploads/{filename}"
        client.upload_fileobj(file, self.bucket_name, key)
        return f"s3://{self.bucket_name}/{key}"


def get_storage_service(app=None):
    return StorageService(app=app)
