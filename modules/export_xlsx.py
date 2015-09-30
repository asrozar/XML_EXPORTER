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
import modules.db_connect
from classes.db_tables import InventoryHost

try:
  import xlsxwriter
except ImportError:
  print('Installing XlsxWriter..')
  os.system('pip3 install XlsxWriter')
  import xlsxwriter


def exporter():

  """Connect to the database"""
  Session = modules.db_connect.connect()
  session = Session()
  report = xlsxwriter.Workbook('perception_report.xlsx')
  top_row_format = report.add_format({'bold': True})
  top_row_format.set_border(style=1)
  top_row_format.set_bg_color('#B8B8B8')

  """Black row format at the top of each host detailed info"""
  black_row_format = report.add_format()
  black_row_format.set_border(style=1)
  black_row_format.set_bg_color('#000000')

  """Detailed host row format"""
  host_row_format = report.add_format()
  host_row_format.set_border(style=1)
  host_row_format.set_bg_color('#CCCCCC')

  """Format for text in row with host info"""
  host_row_wrapped_format = report.add_format()
  host_row_wrapped_format.set_border(style=1)
  host_row_wrapped_format.set_bg_color('#CCCCCC')
  host_row_wrapped_format.set_text_wrap('vjustify')

  """Format description row in NSE output"""
  host_nse_output_top_format = report.add_format({'bold': True})
  host_nse_output_top_format.set_border(style=1)
  host_nse_output_top_format.set_bg_color('#B8B8B8')

  """Format test row in NSE output"""
  host_nse_output_format = report.add_format()
  host_nse_output_format.set_border(style=1)
  host_nse_output_format.set_bg_color('#CCCCCC')

  """Build the host_overview_worksheet"""
  host_overview_worksheet = report.add_worksheet()

  """Build the host_detail_worksheet"""
  host_detail_worksheet = report.add_worksheet()

  """Size up the overview worksheet"""
  host_overview_worksheet.set_column('B:B', 24)
  host_overview_worksheet.set_column('C:C', 15)
  host_overview_worksheet.set_column('D:D', 15)
  host_overview_worksheet.set_column('E:E', 15)
  host_overview_worksheet.set_column('F:F', 15)
  host_overview_worksheet.set_column('G:G', 20)
  host_overview_worksheet.set_column('H:H', 15)

  """Size up the detail worksheet"""
  host_detail_worksheet.set_column('B:B', 38)
  host_detail_worksheet.set_column('C:C', 16)
  host_detail_worksheet.set_column('D:D', 16)
  host_detail_worksheet.set_column('E:E', 28)
  host_detail_worksheet.set_column('F:F', 15)
  host_detail_worksheet.set_column('H:G', 20)
  host_detail_worksheet.set_column('H:H', 25)
  host_detail_worksheet.set_column('I:I', 10)

  """Description row for host overview"""
  host_overview_worksheet.write('B2', 'Hostname', top_row_format)
  host_overview_worksheet.write('C2', 'IP v4 Address', top_row_format)
  host_overview_worksheet.write('D2', 'IP v6 Address', top_row_format)
  host_overview_worksheet.write('E2', 'MAC Address', top_row_format)
  host_overview_worksheet.write('F2', 'MAC Vendor', top_row_format)
  host_overview_worksheet.write('G2', 'Operating System', top_row_format)
  host_overview_worksheet.write('H2', 'Host Type', top_row_format)

  """Query the database for the hosts"""
  inventory_hosts = session.query(InventoryHost).all()

  """Build overview worksheet"""
  overview_row = 2
  overview_col = 1
  for host in inventory_hosts:
      host_overview_worksheet.write(overview_row, overview_col, host.host_name, host_row_format)
      host_overview_worksheet.write(overview_row, overview_col + 1, host.ipv4_addr, host_row_format)
      host_overview_worksheet.write(overview_row, overview_col + 2,  host.ipv6_addr, host_row_format)
      host_overview_worksheet.write(overview_row, overview_col + 3, host.macaddr, host_row_format)
      host_overview_worksheet.write(overview_row, overview_col + 4, host.mac_vendor.name, host_row_format)
      host_overview_worksheet.write(overview_row, overview_col + 5, host.product.name, host_row_format)
      host_overview_worksheet.write(overview_row, overview_col + 6, host.host_type, host_row_format)
      overview_row += 1

  """Build detailed worksheet"""
  detail_row = 2
  detail_col = 1
  for host in inventory_hosts:

      """Add the black row to start host detail info"""
      host_detail_worksheet.set_row(detail_row, 5)
      host_detail_worksheet.write(detail_row, detail_col, '', black_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 1, '', black_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 2, '', black_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 3, '', black_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 4, '', black_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 5, '', black_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 6, '', black_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 7, '', black_row_format)
      detail_row += 1

      """Add row detail info"""
      host_detail_worksheet.write(detail_row, detail_col, 'Hostname', top_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 1, 'IP v4 Address', top_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 2, 'IP v6 Address', top_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 3, 'MAC Address', top_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 4, 'MAC Vendor', top_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 5, 'Host Type', top_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 6, 'Operating System', top_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 7, 'Version', top_row_format)
      detail_row += 1

      """Add host info"""
      host_detail_worksheet.write(detail_row, detail_col, host.host_name, host_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 1, host.ipv4_addr, host_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 2,  host.ipv6_addr, host_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 3, host.macaddr, host_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 4, host.mac_vendor.name, host_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 5, host.host_type, host_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 6, host.product.name, host_row_format)
      host_detail_worksheet.write(detail_row, detail_col + 7, host.product.version, host_row_format)
      detail_row += 2

      """If there is no host nse script, just say so."""
      if not host.host_nse_scripts:
          host_detail_worksheet.write(detail_row, detail_col, 'Host NSE Script Name', top_row_format)
          host_detail_worksheet.merge_range(detail_row, detail_col + 1, detail_row, detail_col + 7,
                                            'Output', top_row_format)
          detail_row += 1
          host_detail_worksheet.write(detail_row, detail_col, 'No Script Name', host_row_format)
          host_detail_worksheet.merge_range(detail_row, detail_col + 1, detail_row, detail_col + 7,
                                            'No Script Output', host_row_wrapped_format)
          detail_row += 2
      else:

          """Add the row detail"""
          host_detail_worksheet.write(detail_row, detail_col, 'Host NSE Script Name', top_row_format)
          host_detail_worksheet.merge_range(detail_row, detail_col + 1, detail_row, detail_col + 7,
                                            'Output', top_row_format)
          detail_row += 1

          """Grab all the scripts"""
          for host_scripts in host.host_nse_scripts:

              """Count output the lines so we know what to merge"""
              lines = host_scripts.output.count('\n')

              if lines > 0:

                  """Merge the rows and write the name and output"""
                  host_detail_worksheet.merge_range(detail_row, detail_col, detail_row + lines, detail_col,
                                                    host_scripts.name, host_row_format)
                  host_detail_worksheet.merge_range(detail_row, detail_col + 1, detail_row + lines, detail_col + 7,
                                                    host_scripts.output, host_row_wrapped_format)
                  detail_row += 1
              else:

                  """Single line output"""
                  host_detail_worksheet.write(detail_row, detail_col, host_scripts.name, host_row_format)
                  host_detail_worksheet.merge_range(detail_row, detail_col + 1, detail_row + lines, detail_col + 7,
                                                    host_scripts.output, host_row_wrapped_format)
                  detail_row += 1

      if not host.inventory_svcs:

          """If there are no services for this host tell me"""
          host_detail_worksheet.write(detail_row, detail_col, 'Protocol', top_row_format)
          host_detail_worksheet.write(detail_row, detail_col + 1, 'Port', top_row_format)
          host_detail_worksheet.write(detail_row, detail_col + 2, 'Name', top_row_format)
          host_detail_worksheet.write(detail_row, detail_col + 3, 'Svc Product', top_row_format)
          host_detail_worksheet.write(detail_row, detail_col + 4, 'Extra Info', top_row_format)
          host_detail_worksheet.write(detail_row, detail_col + 5, 'Product', top_row_format)
          host_detail_worksheet.write(detail_row, detail_col + 6, 'Version', top_row_format)
          host_detail_worksheet.write(detail_row, detail_col + 7, 'Update', top_row_format)
          detail_row += 1

          host_detail_worksheet.write(detail_row, detail_col, 'no services', host_row_format)
          host_detail_worksheet.write(detail_row, detail_col + 1, 'no services', host_row_format)
          host_detail_worksheet.write(detail_row, detail_col + 2, 'no services', host_row_format)
          host_detail_worksheet.write(detail_row, detail_col + 3, 'no services', host_row_format)
          host_detail_worksheet.write(detail_row, detail_col + 4, 'no services', host_row_format)
          host_detail_worksheet.write(detail_row, detail_col + 5, 'no services', host_row_format)
          host_detail_worksheet.write(detail_row, detail_col + 6, 'no services', host_row_format)
          host_detail_worksheet.write(detail_row, detail_col + 7, 'no services', host_row_format)
          detail_row += 1

      else:
          for ports in host.inventory_svcs:

              """Host services row info"""
              detail_row += 1
              host_detail_worksheet.write(detail_row, detail_col, 'Protocol', top_row_format)
              host_detail_worksheet.write(detail_row, detail_col + 1, 'Port', top_row_format)
              host_detail_worksheet.write(detail_row, detail_col + 2, 'Name', top_row_format)
              host_detail_worksheet.write(detail_row, detail_col + 3, 'Svc Product', top_row_format)
              host_detail_worksheet.write(detail_row, detail_col + 4, 'Extra Info', top_row_format)
              host_detail_worksheet.write(detail_row, detail_col + 5, 'Product', top_row_format)
              host_detail_worksheet.write(detail_row, detail_col + 6, 'Version', top_row_format)
              host_detail_worksheet.write(detail_row, detail_col + 7, 'Update', top_row_format)
              detail_row += 1

              """Write the service info"""
              host_detail_worksheet.write(detail_row, detail_col, ports.protocol, host_row_format)
              host_detail_worksheet.write(detail_row, detail_col + 1, ports.portid, host_row_format)
              host_detail_worksheet.write(detail_row, detail_col + 2, ports.name, host_row_format)
              host_detail_worksheet.write(detail_row, detail_col + 3, ports.svc_product, host_row_format)
              host_detail_worksheet.write(detail_row, detail_col + 4, ports.extra_info, host_row_format)
              try:

                  """There may not be product info, but try."""
                  host_detail_worksheet.write(detail_row, detail_col + 5, ports.product.name, host_row_format)
                  host_detail_worksheet.write(detail_row, detail_col + 6, ports.product.version, host_row_format)
                  host_detail_worksheet.write(detail_row, detail_col + 7, ports.product.product_update,
                                              host_row_format)
                  detail_row += 1
              except AttributeError:

                  """Just write unknown if there is no product info"""
                  host_detail_worksheet.write(detail_row, detail_col + 5, 'unknown', host_row_format)
                  host_detail_worksheet.write(detail_row, detail_col + 6, 'unknown', host_row_format)
                  host_detail_worksheet.write(detail_row, detail_col + 7, 'unknown', host_row_format)
                  detail_row += 1

              if not ports.svc_nse_scripts:

                  """If there is no NSE script info just say so."""
                  host_detail_worksheet.write(detail_row, detail_col, 'Svc NSE Script Name', top_row_format)
                  host_detail_worksheet.merge_range(detail_row, detail_col + 1, detail_row, detail_col + 7,
                                                    'Output', top_row_format)
                  detail_row += 1
                  host_detail_worksheet.write(detail_row, detail_col, 'No Script Name', host_row_format)
                  host_detail_worksheet.merge_range(detail_row, detail_col + 1, detail_row, detail_col + 7,
                                                    'No Script Output', host_row_wrapped_format)
                  detail_row += 2

              else:

                  """Service Script row detail"""
                  host_detail_worksheet.write(detail_row, detail_col, 'Svc NSE Script Name', top_row_format)
                  host_detail_worksheet.merge_range(detail_row, detail_col + 1, detail_row, detail_col + 7,
                                                    'Output', top_row_format)
                  detail_row += 1

                  """Grab all the scripts"""
                  for nse_scripts in ports.svc_nse_scripts:

                      """Count the lines in the output for merging"""
                      lines = nse_scripts.output.count('\n')

                      if lines > 0:

                          """Merge the rows and write the name and output"""
                          host_detail_worksheet.merge_range(detail_row, detail_col, detail_row + lines, detail_col,
                                                            nse_scripts.name, host_row_format)
                          host_detail_worksheet.merge_range(detail_row, detail_col + 1, detail_row + lines, detail_col + 7,
                                                            nse_scripts.output, host_row_wrapped_format)
                          detail_row += 1
                      else:

                          """Single line output"""
                          host_detail_worksheet.write(detail_row, detail_col, nse_scripts.name, host_row_format)
                          host_detail_worksheet.merge_range(detail_row, detail_col + 1, detail_row + lines,
                                                            detail_col + 7, nse_scripts.output,
                                                            host_row_wrapped_format)
                          detail_row += 1

          detail_row += 1
  report.close()
  session.close()
