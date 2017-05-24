from django.shortcuts import render
from .models import Task
from .forms import NewTask
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404


def index(request):
    """
    Root page view. Just shows a list of values currently available.
    """
    # for task in Task.objects.all():
    #     task.results = json.loads(task.results)
    #     task.save()
    form = NewTask()
    if request.method == 'POST':
        if '_create' in request.POST:
            form = NewTask(request.POST)
            if form.is_valid():
                form.save()
                return HttpResponseRedirect('/')
    return render(request, "index.html", {
        "tasks": Task.objects.all(),
        "form": form
    })


def delete(request, id):
    get_object_or_404(Task, pk=id).delete()
    return HttpResponseRedirect('/')
