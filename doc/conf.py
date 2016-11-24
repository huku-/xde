from better import better_theme_path

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.todo',
    'sphinx.ext.viewcode',
]

project = u'XDE'
version = u'2.0'
release = u'2.0'
copyright = u'2016, huku'
author = u'huku <huku@grhack.net>'
show_authors = True
language = 'en'

source_suffix = '.rst'
master_doc = 'index'
autodoc_member_order = 'bysource'
pygments_style = 'sphinx'
todo_include_todos = True

templates_path = []
exclude_patterns = []

html_theme_path = [better_theme_path]
html_theme = 'better'
# html_theme = 'alabaster'
# html_theme = 'classic'
html_theme_options = {}
# html_logo = None
# html_favicon = None
# html_static_path = ['_static']
# html_extra_path = []
# html_last_updated_fmt = None
# html_use_smartypants = True
# html_sidebars = {}
# html_additional_pages = {}
# html_show_sourcelink = True
# html_show_sphinx = True
# html_show_copyright = True
# html_use_opensearch = ''

