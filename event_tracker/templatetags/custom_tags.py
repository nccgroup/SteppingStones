import datetime
import re

from django.template.defaultfilters import register
from django.utils import formats
from django.utils.formats import date_format
from django.utils.html import conditional_escape
from django.utils.safestring import mark_safe
from django.utils.timezone import localtime

from event_tracker.models import HashCatMode, Event


@register.simple_tag
def datetime_format_moment():
    # Converts the Django regional datetime format into a format understandable by momentjs, as used by datatables
    return (formats.get_format("SHORT_DATE_FORMAT").upper()
            .replace("D", "DD").replace("M", "MM").replace("Y","YYYY")
            + " HH:mm")


@register.filter
def status_to_class(value):
    if value == "UNK":
        return "bg-light"
    elif value == "FUL":
        return "bg-success"
    elif value == "PAR":
        return "bg-warning"
    elif value == "NEG":
        return "bg-danger"


@register.filter
def status_to_html_color(value):
    if value in ["UNK", "N/A"]:
        return ""
    elif value == "FUL":
        return "green"
    elif value == "PAR":
        return "yellow"
    elif value == "NEG":
        return "red"

@register.filter
def status_to_word_color(value):
    if value in ["UNK", "N/A"]:
        return ""
    elif value == "FUL":
        return "DarkSeaGreen"
    elif value == "PAR":
        return "lemonchiffon"
    elif value == "NEG":
        return "darkred"


@register.filter
def prevented_enum_to_label(value):
    return Event.PreventedChoices(value).label


@register.filter
def detected_enum_to_label(value):
    return Event.DetectedChoices(value).label

@register.filter
def firstsentence(value):
    return re.split(r"(\.\s|\n)", value)[0].strip()


@register.filter
def afterfirstsentence(value):
    return value[len(firstsentence(value)) + 1:].lstrip()


@register.filter(needs_autoescape=True)
def breakonpunctuation(value, autoescape=True):
    if autoescape:
        esc = conditional_escape
    else:
        esc = lambda x: x
    return mark_safe(re.sub(r"([\\/.@\-_&%])", r"<wbr>\1", esc(value)))

@register.filter
def percentiletoheatmapcolour(value):
    if value <= 0.20:
        return "informational"
    elif value <= 0.40:
        return "low"
    elif value <= 0.60:
        return "medium"
    elif value <= 0.80:
        return "high"
    else:
        return "critical"

@register.filter
def percent_to_words(value):
    if value == 0:
        return "none"
    elif value <= 0.20:
        return "minimal"
    elif value >= 0.80 and value < 1.00:
        return "most"
    elif value >= 1.00:
        return "all"
    else:
        return "some"

@register.filter
def percent_to_goodness_colour(value):
    if value == 0:
        return "high"
    elif value <= 0.20:
        return "medium"
    elif value >= 0.80 and value < 1.00:
        return "informational"
    elif value >= 1.00:
        return "green"
    else:
        return "low"

@register.filter
def getdictentry(value, key):
    return value[key]


@register.filter(needs_autoescape=True)
def addnewlineifshorterthan(value, length, autoescape=True):
    if autoescape:
        esc = conditional_escape
    else:
        esc = lambda x: x

    if len(value) < length:
        return mark_safe(esc(value) + "\n\n&nbsp;")
    else:
        return mark_safe(esc(value))

@register.filter
def mitredescriptiontomarkdown(value):
    # Remove citations, we're not tracking the URLs they point to
    value = re.sub(r"\(Citation: .+?\)", "", value)

    # Turn code blocks into markdown inline code - need to swallow inner whitespace too
    value = re.sub(r'&lt;code&gt;\s*', r"`", value)
    value = re.sub(r'\s*&lt;/code&gt;', r"`", value)

    # Any angle brackets left are intended to be angle brackets (XSS risk, but we trust MITRE, right?)
    value = re.sub(r'&lt;', r"<", value)
    value = re.sub(r'&gt;', r">", value)

    return value

def escape_if_outside_code_or_comment(match):
    for codeblock in re.finditer(r"(`)(?:(?=(\\?))\2.)*?`", match.string):
        if codeblock.start() < match.start() and codeblock.end() > match.end():  # If match is inside codeblock
            return match.group(0)

    for commentblock in re.finditer(r"(\[&gt;&gt;|\[>>)(?:(?=(\\?))\2.)*?]", match.string):
        if commentblock.start() <= match.start() and commentblock.end() >= match.end():  # If match is inside codeblock
            return match.group(0)

    return '\\' + match.group(0)

@register.filter
def tidytextformarkdown(value, allow_links=False):
    # Replace excessive newlines with just a pair of newlines
    value = re.sub("\n{3,}", "\n\n", value)

    # Escape the escape char
    value = re.sub(r'\\', escape_if_outside_code_or_comment, value)

    if allow_links:
        # Use complex regex to find [ and ] not immediately followed by a (...)
        value = re.sub(r"\[(?![^]]+]\()", escape_if_outside_code_or_comment, value)
        value = re.sub(r"](?!\()", escape_if_outside_code_or_comment, value)
    else:
        # Simply escape square brackets as they are used for links in markdown
        value = re.sub(r"\[", escape_if_outside_code_or_comment, value)
        value = re.sub("]", escape_if_outside_code_or_comment, value)

    return value

@register.filter
def consolidatelinebreaks(value):
    value = re.sub("\n+", "\n\n", value)

    return value


def matchtohtmlspaces(match):
    """
    Returns a string of "&nbsp;" equal to the length of the match
    """
    start, end = match.span()

    return "&nbsp;" * (end - start)


@register.filter(needs_autoescape=True)
def preventunexpectedcodeblocks(value, autoescape=True):
    """
    kramdown treats lines starting with spaces or tabs as code blocks. But no one uses that functionality, so we assume
    that's not what was intended and use HTML entities to mask those spaces. Tabs are collapsed to a single space
    to reduce the amount of whitespace in reports.
    """
    if autoescape:
        esc = conditional_escape
    else:
        esc = lambda x: x

    pattern = re.compile(r"^([ \t])+", flags=re.MULTILINE)
    return mark_safe(pattern.sub(matchtohtmlspaces, esc(value)))


@register.filter
def linebreaksword(value):
    if not value:
        return ""

    value = "\n" + value  # Prefix with a newline as we use this primarily after bolding the first sentence.
    value = re.sub("\n+", "<br/>\n", value)

    return mark_safe(value)


@register.filter
def epoch_to_ts(epoch_time):
    try:
        return datetime.datetime.fromtimestamp(epoch_time, tz=datetime.timezone.utc)
    except:
        return f"Could not convert: {epoch_time}"


@register.filter
def render_ts_utc(value):
    return f"{date_format(value, 'SHORT_DATE_FORMAT')} {value.strftime('%H:%M')}"


@register.filter
def render_ts_to_ts_utc(value, until):
    if value.date() == until.date():
        return f"{render_ts_utc(value)} to {until.strftime('%H:%M')}"
    else:
        return f"{render_ts_utc(value)} to {render_ts_utc(until)}"


@register.filter
def render_ts_local(value):
    if isinstance(value, datetime.datetime):
        return f"{date_format(value, 'SHORT_DATE_FORMAT')} {localtime(value).strftime('%H:%M')}"
    else:
        return f"Not a datetime: {value}"


@register.filter
def hash_type_name(value):
    if not value:
        return "Hash"

    return HashCatMode(value).name + " hash"

@register.filter
def as_percentage(value):
    return "{0:.0%}".format(float(value))

@register.filter
def underscore_to_space(value):
    return value.replace("_", " ")

@register.filter
def path_relative_to_host(value, host):
    return re.sub(rf"\\\\{host}[^\\]*\\(?P<drive>[A-Z])\$(?P<path>\\.*)", r"\g<drive>:\g<path>", value, flags=re.IGNORECASE)

@register.filter
def exclude(value, exclusion):
    result = list(value)
    if exclusion in result:
        result.remove(exclusion)
    return result

@register.filter
def redact(value, plain_text_chars=2):
    return value[:plain_text_chars] + (len(value) - (plain_text_chars * 2)) * '\\*' + value[-plain_text_chars:]