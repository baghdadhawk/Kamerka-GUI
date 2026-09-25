from django import template

from app_kamerka.banner_utils import looks_like_generic_http_response

register = template.Library()


@register.filter(name='looks_like_generic_http_response')
def looks_like_generic_http_response_filter(value):
    return looks_like_generic_http_response(value)
