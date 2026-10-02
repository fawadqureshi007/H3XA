from .user_scanner import UserScanner
from .holehe import Holehe
from .h8mail import H8mail
from .ghunt import GHunt
from .tookie import Tookie
from .userrecon import UserRecon
from .spiderfoot import SpiderFoot
from .osintgram import Osintgram
from .phoneinfo import PhoneInfo

ALL = {a.name: a for a in (UserScanner, Holehe, H8mail, GHunt, Tookie, UserRecon, SpiderFoot, Osintgram, PhoneInfo)}
