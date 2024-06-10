import pathlib

def split_path(path):
    """
    Infers the operating system in use based on heuristics and splits the path into filename (if there is one)
    and directory name.

    Returns a tuple of parent directory (excluding trailing file_sep), file_sep, and filename (or empty string if path
    refers to a directory)
    """
    forward_slashes = path.count("/")
    back_slashes = path.count("\\")

    if forward_slashes > back_slashes:
        path_obj = pathlib.PurePosixPath(path)
        if path.endswith("/"):
            return str(path_obj), "/", ""
        else:
            # Parent of "justafile" is a path object wrapping "."
            return str(path_obj.parent) if path_obj.parent != pathlib.PurePosixPath("justafile").parent else "",\
                   "/", str(path_obj.name)
    else:
        path_obj = pathlib.PureWindowsPath(path)
        if path.endswith("\\"):
            return str(path_obj), "\\", ""
        else:
            # Parent of "justafile" is a path object wrapping "."
            return str(path_obj.parent) if path_obj.parent != pathlib.PureWindowsPath("justafile").parent else "",\
                   "\\", str(path_obj.name)

