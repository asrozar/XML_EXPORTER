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

from sqlalchemy import Column, Integer, Text, ForeignKey, Sequence, TIMESTAMP, String
from sqlalchemy.orm import relationship
from sqlalchemy.dialects import postgresql
from base.Base import Base
import datetime


def _get_date():
  return datetime.datetime.now()


class HostNseScript(Base):
  __tablename__ = 'host_nse_scripts'

  id = Column(Integer, Sequence('host_nse_scripts_id_seq'), primary_key=True, nullable=False)

  """Relation to host"""
  host_id = Column(Integer, ForeignKey('inventory_hosts.id'))
  host = relationship('InventoryHost', backref='host_nse_scripts', order_by=id)

  name = Column(Text, nullable=False)
  output = Column(Text, nullable=False)


class SvcNseScript(Base):
  __tablename__ = 'svc_nse_scripts'

  id = Column(Integer, Sequence('svc_nse_scripts_id_seq'), primary_key=True, nullable=False)

  """Relation to host"""
  svc_id = Column(Integer, ForeignKey('inventory_svcs.id', ondelete='cascade'))
  svc = relationship('InventorySvc', backref='svc_nse_scripts', order_by=id)

  name = Column(Text, nullable=False)
  output = Column(Text, nullable=False)


class Vendor(Base):
  __tablename__ = 'vendors'

  id = Column(Integer, Sequence('vendors_id_seq'), primary_key=True, nullable=False)
  name = Column(Text, unique=True, nullable=False)


class Product(Base):
  __tablename__ = 'products'

  id = Column(Integer, Sequence('products_id_seq'), primary_key=True, nullable=False)

  product_type = Column(Text, nullable=False)

  """Relation to tie vendors to products"""
  vendor_id = Column(Integer, ForeignKey('vendors.id'), nullable=False)
  vendor = relationship('Vendor', backref='products', order_by=id)

  name = Column(Text, nullable=False)
  version = Column(Text)
  product_update = Column(Text)
  edition = Column(Text)
  language = Column(Text)


class InventoryHost(Base):
  __tablename__ = 'inventory_hosts'

  id = Column(Integer, Sequence('inventory_hosts_id_seq'), primary_key=True, nullable=False)
  ipv4_addr = Column(postgresql.INET, unique=True)
  ipv6_addr = Column(postgresql.INET)
  macaddr = Column(postgresql.MACADDR)
  host_type = Column(Text)

  """Relation to tie mac address vendors to inventory hosts"""
  mac_vendor_id = Column(Integer, ForeignKey('mac_vendors.id'))
  mac_vendor = relationship('MACVendor', backref='inventory_hosts', order_by=id)

  state = Column(Text)
  host_name = Column(Text)

  """Relation to tie an OS inventory hosts"""
  product_id = Column(Integer, ForeignKey('products.id', ondelete='cascade'))
  product = relationship('Product', backref='inventory_hosts', order_by=id)

  arch = Column(Text)

  info = Column(Text)
  comments = Column(Text)

  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
  updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)


class InventorySvc(Base):
  __tablename__ = 'inventory_svcs'

  id = Column(Integer, Sequence('inventory_svcs_id_seq'), primary_key=True, nullable=False)

  """Relation to inventory hosts"""
  host_id = Column(Integer, ForeignKey('inventory_hosts.id'))
  host = relationship('InventoryHost', backref='inventory_svcs', order_by=id)

  protocol = Column(Text)
  portid = Column(Integer)
  name = Column(Text)
  svc_product = Column(Text)
  extra_info = Column(Text)

  """Relation to tie products to inventory services"""
  product_id = Column(Integer, ForeignKey('products.id'))
  product = relationship('Product', backref='inventory_svcs', order_by=id)

  created_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class MACVendor(Base):
  __tablename__ = 'mac_vendors'

  id = Column(Integer, Sequence('mac_vendors_id_seq'), primary_key=True, nullable=False)
  name = Column(Text, unique=True)
