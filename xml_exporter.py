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
import argparse
import modules.xml_parser
import modules.db_connect
import modules.export_xlsx


def main():
  parser = argparse.ArgumentParser('--nmap_xml, --xlsx_export, --drop_all')

  parser.add_argument('--nmap_xml',
                      dest='nmap_xml',
                      type=str,
                      help='NMAP XML file to parse.')

  parser.add_argument('--xlsx_export',
                      dest='xlsx_export',
                      action='store_true',
                      help='Export to XLSX after parsing.')

  parser.add_argument('--drop_all',
                      dest='drop_all',
                      action='store_true',
                      help='Drop all tables from the database.'),

  parser.add_argument('--test_yml_file',
                      dest='test_yml_file',
                      action='store_true',
                      help='Test the Data Base file and connection')

  args = parser.parse_args()
  nmap_xml = args.nmap_xml
  xlsx_export = args.xlsx_export
  drop_all = args.drop_all
  test_yml_file = args.test_yml_file

  if test_yml_file:
    try:
      modules.db_connect.connect()
    except TypeError as e:
      print('Some thing went wrong, Error: %s' % e)
      exit()
    print('YML file is good.')
    exit()

  if drop_all:
      clear_screen()
      if input('Are you sure?: ') == 'yes':
          modules.db_connect.connect_and_drop_all()
          clear_screen()
          print('Dropped all tables.')
          exit()

  clear_screen()

  if nmap_xml:
      try:
          modules.db_connect.connect_and_create_db()
      except:
          print('Could not create to the database, did you modify config/database.yml?')
          exit()
      try:
          modules.xml_parser.parse_nmap_xml(nmap_xml)
          clear_screen()
          print('Done.')
      except IsADirectoryError:
          print('I can not read an entire directory')
          exit()

      if xlsx_export:
          clear_screen()
          print('Generating report..')
          modules.export_xlsx.exporter()
          clear_screen()
          print('Done.')
          exit()
      exit()

  if xlsx_export:
      clear_screen()
      print('Generating report..')
      modules.export_xlsx.exporter()
      clear_screen()
      print('Done.')
      exit()

  else:
      clear_screen()
      print('I need arguments.')
      parser.print_help()
      exit()


def clear_screen():
  os.system('clear')

if __name__ == '__main__':
  try:
    main()
  except (IOError, SystemExit):
    raise
  except KeyboardInterrupt:
    print('Crtl+C Pressed. Shutting down.')
