import os
from pathlib import Path


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
            return os.getenv('UPLOAD_FOLDER', str(Path(__file__).resolve().parent / 'static' / 'uploads'))
        return self.app.config.get('UPLOAD_FOLDER', str(Path(__file__).resolve().parent / 'static' / 'uploads'))

    @property
    def bucket_name(self):
        if self.app is None:
            return os.getenv('STORAGE_BUCKET', 'mini-isms-local')
        return self.app.config.get('STORAGE_BUCKET', 'mini-isms-local')

    def save(self, file, filename):
        if self.backend == 's3':
            return self._save_to_s3(file, filename)
        return self._save_to_local(file, filename)

    def _save_to_local(self, file, filename):
        target_dir = Path(self.upload_root)
        target_dir.mkdir(parents=True, exist_ok=True)
        target_path = target_dir / filename
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
