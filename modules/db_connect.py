#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
(C) Copyright [2015] InfoSec Consulting, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
 
http://www.apache.org/licenses/LICENSE-2.0
 
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

         ...
    .:::|#:#|::::.
 .:::::|##|##|::::::.
 .::::|##|:|##|:::::.
  ::::|#|:::|#|:::::
  ::::|#|:::|#|:::::
  ::::|##|:|##|:::::
  ::::.|#|:|#|.:::::
  ::|####|::|####|::
  :|###|:|##|:|###|:
  |###|::|##|::|###|
  |#|::|##||##|::|#|
  |#|:|##|::|##|:|#|
  |#|##|::::::|##|#|
   |#|::::::::::|#|
    ::::::::::::::
      ::::::::::
       ::::::::
        ::::::
          ::
"""

__author__ = 'Avery Rozar'

import os
import sys
import classes.db_tables

try:
    import yaml
except ImportError:
    print('Installing PyYmal..')
    os.system('pip3 install PyYAML')
    import yaml

try:
    import psycopg2
except ImportError:
    print('Installing Psycopg2..')
    os.system('pip3 install psycopg2')
    import psycopg2

try:
    import sqlalchemy
    from sqlalchemy import Column, String, Text, Integer, ForeignKey, Sequence, create_engine, MetaData
    from sqlalchemy.orm import relationship, sessionmaker
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.engine.url import URL
except ImportError:
    print('Installing SQLAlchemy..')
    os.system('pip3 install SQLAlchemy')
    import sqlalchemy
    from sqlalchemy import Column, String, Text, Integer, ForeignKey, Sequence, create_engine, MetaData
    from sqlalchemy.orm import relationship, sessionmaker
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.engine.url import URL

Session = sessionmaker()


def connect():

    db_yml = open('config/database.yml', 'r')
    db_info = yaml.safe_load(db_yml)
    cursor = None

    try:
        Session = sessionmaker()
        engine = create_engine(URL(**db_info), pool_size=20)
        Session.configure(bind=engine)
        return Session
    except sqlalchemy.exc.OperationalError as e:
        print(e)
        sys.exit(1)
    finally:
        if cursor:
            cursor.close()


def connect_and_create_db():

    db_yml = open('config/database.yml', 'r')
    db_info = yaml.safe_load(db_yml)
    cursor = None

    try:
        engine = create_engine(URL(**db_info))
        Session.configure(bind=engine)
        classes.db_tables.Base.metadata.create_all(engine)
        return Session
    except sqlalchemy.exc.OperationalError as e:
        print(e)
        sys.exit(1)
    finally:
        if cursor:
            cursor.close()


def connect_and_drop_all():

    db_yml = open('config/database.yml', 'r')
    db_info = yaml.safe_load(db_yml)
    cursor = None

    try:
        engine = create_engine(URL(**db_info))
        Session.configure(bind=engine)
        classes.db_tables.Base.metadata.drop_all(engine)
        return Session
    except sqlalchemy.exc.OperationalError as e:
        print(e)
        sys.exit(1)
    finally:
        if cursor:
            cursor.close()