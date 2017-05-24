from channels.generic.websockets import WebsocketDemultiplexer

from .models import TaskBinding


class Demultiplexer(WebsocketDemultiplexer):
    consumers = {
        "taskstr": TaskBinding.consumer,
    }

    groups = ["binding.tasks"]
