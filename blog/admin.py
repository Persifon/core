from django.contrib import admin
from markdownx.admin import MarkdownxModelAdmin

from .models import Post, Category


admin.site.register(Post, MarkdownxModelAdmin)
admin.site.register(Category)
