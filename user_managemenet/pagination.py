from rest_framework.pagination import PageNumberPagination

page_count = 10

def page_serializer(paginator, page_obj, page, data):
    serialized_data = {
        'count' : paginator.count,
        'current_page' : int(page),
        'total_pages' : paginator.num_pages,
        'has_prevous_page' : page_obj.has_previous(),
        'has_next_page' : page_obj.has_next(),
        'data' : data
    }
    
    return serialized_data

class StandardPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page'