from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import pandas as pd

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

def parse_evtx(path, source):
    records = []

    with Evtx(path) as log:
        for record in log.records():
            xml = ET.fromstring(record.xml())
            data = {"source": source}

            # Timestamp
            time = xml.find(".//e:TimeCreated", NS)
            if time is not None:
                data["timestamp"] = time.attrib.get("SystemTime")

            # Event ID
            event_id = xml.find(".//e:EventID", NS)
            if event_id is not None:
                data["event_id"] = event_id.text

            # Computer name
            computer = xml.find(".//e:Computer", NS)
            if computer is not None:
                data["computer"] = computer.text

            # EventData fields
            for elem in xml.findall(".//e:EventData/e:Data", NS):
                name = elem.attrib.get("Name")
                if name:
                    data[name] = elem.text

            records.append(data)

    return pd.DataFrame(records)
