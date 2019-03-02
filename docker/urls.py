from django.contrib import admin
from django.urls import include, path

urlpatterns = [
	path('', include('nmapreport.urls')),
	path('report/', include('nmapreport.urls')),
	path('admin/', admin.site.urls),
]
