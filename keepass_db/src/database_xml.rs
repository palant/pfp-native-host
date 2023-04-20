use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use xmltree::Element;

use super::{ElementIterator, Entry, Error, InnerHeader, XMLHelpers};
use crate::io::{Deserialize, Serialize};

fn is_entry(element: &Element) -> bool {
    element.name == "Entry"
}

fn is_group(element: &Element) -> bool {
    element.name == "Group"
        && element
            .get_child("EnableSearching")
            .and_then(|child| child.to_boolean())
            .unwrap_or(true)
}

#[derive(Debug)]
pub struct DatabaseXML {
    xml: Element,
    inner_header: InnerHeader,
}

impl DatabaseXML {
    fn protect(xml: &mut Element, inner_header: &InnerHeader) -> Result<(), Error> {
        let mut cipher = inner_header.cipher.create(&inner_header.key);
        xml.modifier()
            .accept_if(|el| {
                el.name == "Value"
                    && el
                        .attributes
                        .get("Protected")
                        .filter(|attr| attr.to_lowercase() == "true")
                        .is_some()
            })
            .modify(|el| {
                let mut buffer = el.text_content().as_bytes().to_vec();
                cipher.apply_keystream(&mut buffer);

                use base64::Engine;
                el.set_text_content(
                    base64::engine::general_purpose::STANDARD
                        .encode(buffer)
                        .into(),
                );

                Ok(())
            })
    }

    fn unprotect(xml: &mut Element, inner_header: &InnerHeader) -> Result<(), Error> {
        let mut cipher = inner_header.cipher.create(&inner_header.key);
        xml.modifier()
            .accept_if(|el| {
                el.name == "Value"
                    && el
                        .attributes
                        .get("Protected")
                        .filter(|attr| attr.to_lowercase() == "true")
                        .is_some()
            })
            .modify(|el| {
                use base64::Engine;
                let mut buffer = base64::engine::general_purpose::STANDARD
                    .decode(&*el.text_content())
                    .or(Err(Error::CorruptDatabase))?;
                cipher.apply_keystream(&mut buffer);

                el.set_text_content(String::from_utf8(buffer)?.into());
                Ok(())
            })
    }

    pub fn new<R: Read>(input: &mut R) -> Result<Self, Error> {
        let inner_header = InnerHeader::deserialize(input)?;
        let mut xml = Element::parse(input)?;
        DatabaseXML::unprotect(&mut xml, &inner_header)?;

        Ok(Self { xml, inner_header })
    }

    pub fn empty() -> Result<Self, Error> {
        let xml = Element::parse(
            format!(
                r#"
<KeePassFile>
    <Meta>
        <Generator>pfp-native-host</Generator>
        <DatabaseName>Passwords</DatabaseName>
        <DatabaseDescription />
        <MemoryProtection>
            <ProtectTitle>False</ProtectTitle>
            <ProtectUserName>False</ProtectUserName>
            <ProtectPassword>True</ProtectPassword>
            <ProtectURL>False</ProtectURL>
            <ProtectNotes>False</ProtectNotes>
        </MemoryProtection>
    </Meta>
    <Root>
        <Group>
            <UUID>{}</UUID>
            <Name>Root</Name>
            <IsExpanded>True</IsExpanded>
            <EnableSearching>null</EnableSearching>
        </Group>
    </Root>
</KeePassFile>
        "#,
                Entry::generate_uuid()?
            )
            .as_bytes(),
        )?;

        Ok(Self {
            xml,
            inner_header: Default::default(),
        })
    }

    pub fn save<W: Write>(&mut self, output: &mut W) -> Result<(), Error> {
        self.inner_header.reset_cipher()?;
        self.inner_header.serialize(output)?;

        DatabaseXML::protect(&mut self.xml, &self.inner_header)?;
        let config = xmltree::EmitterConfig::new().write_document_declaration(false);
        self.xml.write_with_config(output, config)?;
        DatabaseXML::unprotect(&mut self.xml, &self.inner_header)?;
        Ok(())
    }

    fn get_root_group(&self) -> Option<&Element> {
        let root = self.xml.get_child("Root")?;
        let group = root.get_child("Group")?;
        if is_group(group) {
            Some(group)
        } else {
            None
        }
    }

    fn get_root_group_mut(&mut self) -> Option<&mut Element> {
        let root = self.xml.get_mut_child("Root")?;
        let group = root.get_mut_child("Group")?;
        if is_group(group) {
            Some(group)
        } else {
            None
        }
    }

    pub fn get_protected_fields(&self) -> HashSet<&'static str> {
        let mut result = HashSet::new();
        let fields = [
            "ProtectTitle",
            "ProtectUserName",
            "ProtectPassword",
            "ProtectURL",
            "ProtectNotes",
        ];
        if let Some(meta) = self.xml.get_child("Meta") {
            if let Some(protection) = meta.get_child("MemoryProtection") {
                for field in fields {
                    if protection
                        .get_child(field)
                        .and_then(|child| child.to_boolean())
                        .unwrap_or(false)
                    {
                        result.insert(&field[7..]);
                    }
                }
            }
        }
        result
    }

    pub fn get_entries(&self) -> impl Iterator<Item = Entry> + '_ {
        let elements = if let Some(group) = self.get_root_group() {
            group
                .elements_recursive()
                .recurse_if(is_group)
                .accept_if(is_entry)
        } else {
            ElementIterator::empty()
        };
        elements.filter_map(Entry::from_xml)
    }

    pub fn get_entry(&self, uuid: &str) -> Result<Entry, Error> {
        self.get_entries()
            .find(|entry| entry.uuid == uuid)
            .ok_or(Error::NoSuchEntry)
    }

    pub fn add_entry(&mut self, entry: Entry, protected: &HashSet<&str>) -> Result<String, Error> {
        let group = self.get_root_group_mut().ok_or(Error::MissingRootGroup)?;
        let uuid = entry.uuid.clone();
        group.children.push(entry.to_xml(protected));
        Ok(uuid)
    }

    pub fn remove_entry(&mut self, uuid: &str) -> Result<(), Error> {
        let group = self.get_root_group_mut().ok_or(Error::MissingRootGroup)?;
        if group
            .modifier()
            .recurse_if(is_group)
            .accept_if(is_group)
            .modify(|element| {
                if let Some(index) = element.index_of(|child| {
                    is_entry(child)
                        && matches!(Entry::from_xml(child), Some(entry) if entry.uuid == uuid)
                }) {
                    element.children.remove(index);
                    Err(Error::NoSuchEntry)
                } else {
                    Ok(())
                }
            })
            .is_err()
        {
            Ok(())
        } else {
            Err(Error::NoSuchEntry)
        }
    }

    pub fn update_entry(&mut self, entry: Entry, protected: &HashSet<&str>) -> Result<(), Error> {
        let group = self.get_root_group_mut().ok_or(Error::MissingRootGroup)?;
        if group
            .modifier()
            .recurse_if(is_group)
            .accept_if(is_entry)
            .modify(|element| {
                if element
                    .index_of(|child| child.name == "UUID" && child.text_content() == entry.uuid)
                    .is_some()
                {
                    entry.update_xml(element, protected);
                    Err(Error::NoSuchEntry)
                } else {
                    Ok(())
                }
            })
            .is_err()
        {
            Ok(())
        } else {
            Err(Error::NoSuchEntry)
        }
    }

    const ALIAS_KEY: &str = "PFP_ALIASES";

    pub fn get_aliases(&self) -> HashMap<String, String> {
        let mut result = HashMap::new();
        if let Some(data) = self
            .xml
            .get_child("Meta")
            .and_then(|meta| meta.get_child("CustomData"))
        {
            for element in data.elements() {
                if let Some((key, value)) = element.to_key_value() {
                    if key == Self::ALIAS_KEY {
                        let mut it = value.split('\n');
                        while let (Some(alias), Some(hostname)) = (it.next(), it.next()) {
                            result.insert(alias.to_string(), hostname.to_string());
                        }
                        break;
                    }
                }
            }
        }
        result
    }

    pub fn set_aliases(&mut self, aliases: HashMap<String, String>) {
        let value = aliases
            .into_iter()
            .flat_map(|(key, value)| [key, value])
            .collect::<Vec<_>>()
            .join("\n");

        let meta = if let Some(element) = self.xml.get_mut_child("Meta") {
            element
        } else {
            self.xml.add_element("Meta", |_| {});
            self.xml
                .children
                .last_mut()
                .and_then(|child| child.as_mut_element())
                .unwrap()
        };

        let data = if let Some(element) = meta.get_mut_child("CustomData") {
            element
        } else {
            meta.add_element("CustomData", |_| {});
            meta.children
                .last_mut()
                .and_then(|child| child.as_mut_element())
                .unwrap()
        };

        data.children.retain(|child| {
            !child
                .as_element()
                .and_then(|el| el.to_key_value())
                .map(|(key, _)| key == Self::ALIAS_KEY)
                .unwrap_or(false)
        });
        data.add_element("Item", |el| {
            el.set_key_value(Self::ALIAS_KEY.into(), value.into(), false)
        });
    }

    pub fn add_alias(&mut self, alias: &str, hostname: &str) {
        let mut aliases = self.get_aliases();
        let mut real_hostname = hostname;
        let mut depth = 0;
        const MAX_DEPTH: usize = 10;
        while let Some(hostname) = aliases.get(real_hostname) {
            if hostname == alias || depth >= MAX_DEPTH {
                return;
            }
            real_hostname = hostname;
            depth += 1;
        }
        aliases.insert(alias.to_string(), real_hostname.to_string());
        self.set_aliases(aliases);
    }

    pub fn remove_alias(&mut self, alias: &str) {
        let mut aliases = self.get_aliases();
        if aliases.remove(alias).is_some() {
            self.set_aliases(aliases);
        }
    }
}
