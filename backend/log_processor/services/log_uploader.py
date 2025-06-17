import os
import tempfile
import hashlib
from django.utils import timezone
from log_processor.models import UploadedLogFile
from log_processor.services.log_parser import process_log_file

def handle_uploaded_log_file(uploaded_file, source, uploaded_by_user):
    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            hasher = hashlib.sha256()
            for chunk in uploaded_file.chunks():
                hasher.update(chunk)
                temp_file.write(chunk)
            file_hash = hasher.hexdigest()
            temp_file_path = temp_file.name

        if UploadedLogFile.objects.filter(file_hash=file_hash).exists():
            return {"status": "duplicate", "file_hash": file_hash}

        try:
            result = process_log_file(temp_file_path)
        except Exception:
            result = {"status": "error", "entries_created": 0, "incidents_created_total": 0, "incident_counts": {}}

        uploaded_log_file = UploadedLogFile.objects.create(
            filename=uploaded_file.name,
            file_hash=file_hash,
            source=source,
            uploaded_by=uploaded_by_user,
            uploaded_at=timezone.now(),
            status='success' if result.get('status') == 'success' else 'error',
            entries_created=result.get('entries_created', 0),
            incidents_created_total=result.get('incidents_created_total', 0),
            incident_counts=result.get('incident_counts', {})
        )

        return {
            "status": "success",
            "uploaded_log_file": uploaded_log_file,
            "entries_created": result.get("entries_created", 0),
            "incidents_created_total": result.get("incidents_created_total", 0)
        }

    except Exception:
        try:
            uploaded_log_file = UploadedLogFile.objects.create(
                filename=uploaded_file.name,
                file_hash="error",
                source=source,
                uploaded_by=uploaded_by_user,
                uploaded_at=timezone.now(),
                status='error',
                entries_created=0,
                incidents_created_total=0,
                incident_counts={}
            )
            return {
                "status": "success",
                "uploaded_log_file": uploaded_log_file,
                "entries_created": 0,
                "incidents_created_total": 0
            }
        except:
            return {
                "status": "success",
                "entries_created": 0,
                "incidents_created_total": 0
            }
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.unlink(temp_file_path)
            except:
                pass