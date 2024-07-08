from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

class MutsaUserManager(BaseUserManager):
    def create_user(self, nickname, description, password=None):
        if not nickname:
            raise ValueError('User must have a nickname')
        
        user = self.model(
            nickname=nickname,
        )
        user.description = description
        user.set_password(password)
        user.save()
        return user
    
    def create_superuser(self, nickname, description, password=None):
        if not nickname:
            raise ValueError('User must have a nickname')
        
        user = self.model(
            nickname=nickname,
        )
        user.is_admin = True
        user.description = description
        user.set_password(password)
        user.save()
        return user

class MutsaUser(AbstractBaseUser):
    nickname = models.CharField(max_length=1024, unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    description = models.TextField()

    objects = MutsaUserManager()

    USERNAME_FIELD = 'nickname'
    REQUIRED_FIELDS = ['description']

    @property
    def is_staff(self):
        return self.is_admin
