import os
import tempfile
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .services import process_log_file

@csrf_exempt
def upload_log_file(request):
    if request.method == 'POST' and 'file' in request.FILES:
        uploaded_file = request.FILES['file']
        
        # Save uploaded file to a temporary location
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        file_path = temp_file.name
        
        for chunk in uploaded_file.chunks():
            temp_file.write(chunk)
        temp_file.close()
        
        # Process the file using the existing function
        result = process_log_file(file_path)
        
        # Clean up
        os.unlink(file_path)
        
        return JsonResponse(result)
    
    return JsonResponse({"status": "error", "message": "Please upload a file"}, status=400)