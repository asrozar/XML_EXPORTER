Script for parsing nmap xml output to xlsx format

XML_EXPORTER
==========


XML_EXPORTER is a tool used to parse XML files and insert info into a PostgreSQL database.

XML_EXPORTER will also export host info from the database into an XLSX file.

XML files currently supported are:

    Nmap (the only one at this time, working on more.)

==========================================================================================

First thing to do is edit the config/database.yml.template file.

Add host, database, user, password, and remove the .template in the name.

PostgreSQL 8.4 and ^ are supported.

PostgreSQL 8.4 has been tested.

=================================

Usage:

To get help use the -h, or --help argument.

     python3 xml_exporter.py --help

===================================

Drop all tables from the database.

     python3 xml_exporter.py --drop_all

==========================================================================================

Parse an Nmap scan.

     python3 xml_exporter.py --nmap_xml nmap_scans/example.nmap_scan.xml

==========================================================================================

Parse an Nmap scan, and export to xlsx file.

     python3 xml_exporter.py --nmap_xml nmap_scans/example.nmap_scan.xml --xlsx_export

==========================================================================================

Or just export to xlsx file.

     python3 xml_exporter.py --xlsx_export

==========================================================================================

One open caveat does exist:

    When opening the XLSX file you will receive a warning that some cells are unreadable.

    Just click "repair and open". This is due to the merging of cells during the host detail worksheet.

    I'm working to resolve this issue ASAP.

==========================================================================================
