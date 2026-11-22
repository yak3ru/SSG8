"""Application Control-only sidebar."""
from __future__ import annotations
from dataclasses import dataclass
DEFAULT_PAGE='dashboard'
@dataclass(frozen=True,slots=True)
class NavigationEntry:
    page_id:str
    label:str
    icon:str
@dataclass(frozen=True,slots=True)
class NavigationSection:
    title:str
    entries:tuple[NavigationEntry,...]
NAVIGATION=(
    NavigationSection('OVERVIEW',(NavigationEntry('dashboard','Dashboard','dashboard'),)),
    NavigationSection('PROTECTION',(
        NavigationEntry('applications','Application Protection','apps'),
        NavigationEntry('malware-scan','Scan for Malware','search'),
    )),
    NavigationSection('SECURITY',(
        NavigationEntry('threat-monitor','Threat Monitor','activity'),
        NavigationEntry('incidents','Incidents','shield'),
        NavigationEntry('logs','Security Logs','logs'),
    )),
    NavigationSection('SYSTEM',(
        NavigationEntry('recovery','Recovery Center','refresh'),
        NavigationEntry('about','About SSG8','info'),
    )),
)
ENTRIES_BY_ID={item.page_id:item for section in NAVIGATION for item in section.entries}
SECTION_BY_ID={item.page_id:section.title for section in NAVIGATION for item in section.entries}
def title_for(page_id:str)->str:
    return ENTRIES_BY_ID.get(page_id,NavigationEntry('', 'Unknown','')).label
def section_for(page_id:str)->str:
    return SECTION_BY_ID.get(page_id,'')
