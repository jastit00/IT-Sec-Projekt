import logging

logger = logging.getLogger(__name__)


def filter_fields(data, fields_to_keep):
    return [{k: item[k] for k in fields_to_keep if k in item} for item in data]



def get_filtered_queryset(model, serializer_class, start=None, end=None, fields_to_keep=None):
    queryset = model.objects.all()
    if start:
        queryset = queryset.filter(timestamp__gte=start)
    if end:
        queryset = queryset.filter(timestamp__lte=end)

    queryset = queryset.order_by('-timestamp')

    serializer = serializer_class(queryset, many=True)
    data = serializer.data

    if fields_to_keep:
        return filter_fields(data, fields_to_keep)

    return data