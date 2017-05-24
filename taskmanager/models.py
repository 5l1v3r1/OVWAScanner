from django.db import models
from utils.scanner import performscan
from django.db.models.signals import post_save
from utils.spider import crawler
from channels.binding.websockets import WebsocketBinding
from threading import Thread
from jsonfield import JSONField


# Create your models here.
class Task(models.Model):
    # user = models.ForeignKey(User)
    url = models.URLField(max_length=200)
    portscan = models.BooleanField(default=True)
    nikto = models.BooleanField(default=True)
    cms = models.BooleanField(default=True)
    sql = models.BooleanField(default=True)
    xss = models.BooleanField(default=True)
    csrf = models.BooleanField(default=True)
    recursive = models.BooleanField(default=False)
    # results = models.TextField(max_length=1000000, blank=True)
    results = JSONField(blank=True)
    cookie = models.CharField(max_length=1000, blank=True)
    progress = models.IntegerField(default=0)

    def __str__(self):
        return self.url


class TaskBinding(WebsocketBinding):
    model = Task
    stream = "taskstr"
    fields = ["pk", "url", "progress", "subtask_set", "results"]

    @classmethod
    def group_names(cls, *args, **kwargs):
        return ["binding.tasks"]

    def has_permission(self, user, action, pk):
        return True


class SubTask(models.Model):
    parent = models.ForeignKey(Task)
    url = models.URLField(max_length=200)
    results = models.TextField(max_length=1000, blank=True)
    progress = models.IntegerField(default=0)
    results = JSONField(blank=True)

    def __str__(self):
        return self.url


class SubTaskBinding(WebsocketBinding):
    model = SubTask
    stream = "subtaskstr"
    fields = ["pk", "url", "progress", "parent", "results"]

    @classmethod
    def group_names(cls, *args, **kwargs):
        return ["binding.tasks"]

    def has_permission(self, user, action, pk):
        return True


def create_sub_tasks(sender, instance, created, **kwargs):
    if created:
        urls = []
        if instance.cookie:
            kwargs['cookie'] = instance.cookie
        if instance.recursive is True:
            urls = crawler(instance.url, **kwargs)
        else:
            urls.append(instance.url)
        # instance.save()
        for url in urls:
            subtask = SubTask.objects.create(parent=instance, url=url)
            subtask.save()
        t = Thread(target=performscan, args=([instance]))
        t.start()


post_save.connect(create_sub_tasks, sender=Task)
