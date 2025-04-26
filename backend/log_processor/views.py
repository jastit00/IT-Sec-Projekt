import os
import tempfile
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .services import process_log_file

# TODO maybe add try/except block to catch more errors and return them in the response
@csrf_exempt # disable CSRF protection -> maybe change it later -> angular
def upload_log_file(request):
    if request.method == 'POST' and 'file' in request.FILES:
        uploaded_file = request.FILES['file']
        
        # Save uploaded file to a temporary location
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        file_path = temp_file.name
        
        # Write the uploaded file to the temporary file
        for chunk in uploaded_file.chunks():
            temp_file.write(chunk)
        temp_file.close()
        
        # Process the file using the existing function
        result = process_log_file(file_path)
        
        # Clean up
        os.unlink(file_path)
        
        return JsonResponse(result)
    return JsonResponse({"status": "error", "message": "Please upload a file"}, status=400)