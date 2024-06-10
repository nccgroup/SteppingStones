from django.utils.safestring import mark_safe


def apply_theme(request):
    return {
        "REPORT_FOOTER_IMAGE": mark_safe('<svg width="1" height="1" xmlns="http://www.w3.org/2000/svg"></svg>'),
        "REPORT_FOOTER_TEXT": "Generated with Stepping Stones"
    }