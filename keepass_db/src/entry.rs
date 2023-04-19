use serde::{Serialize, Serializer};
use std::collections::HashSet;
use xmltree::{Element, XMLNode};

use crate::Error;
use crate::XMLHelpers;

#[derive(Serialize, Debug)]
pub struct Entry {
    pub uuid: String,
    pub title: String,
    #[serde(rename = "hostname", serialize_with = "serialize_hostname")]
    pub url: String,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
}

fn get_normalized_hostname(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(hostname) = parsed.host_str() {
            return if let Some(hostname) = hostname.strip_prefix("www.") {
                hostname
            } else if hostname == "invalid.pfp" {
                ""
            } else {
                hostname
            }
            .to_string();
        }
    }
    String::new()
}

fn serialize_hostname<S: Serializer>(url: &str, serializer: S) -> Result<S::Ok, S::Error> {
    let hostname = get_normalized_hostname(url);
    hostname.serialize(serializer)
}

impl Entry {
    pub fn generate_uuid() -> Result<String, Error> {
        let buffer = crate::random::random_vec(16)?;

        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.encode(buffer))
    }

    pub fn new(url: &str, title: &str, username: &str, password: &str) -> Result<Self, Error> {
        Ok(Self {
            uuid: Self::generate_uuid()?,
            url: url.to_string(),
            title: title.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            notes: None,
            tags: None,
        })
    }

    pub fn from_xml(element: &Element) -> Option<Self> {
        let mut uuid = None;
        let mut url = None;
        let mut title = None;
        let mut username = None;
        let mut password = None;
        let mut notes = None;
        let mut tags = None;
        for child in element.elements() {
            match child.name.as_str() {
                "UUID" => uuid = Some(child.text_content().into_owned()),
                "String" => {
                    if let Some((key, value)) = child.to_key_value() {
                        match &*key {
                            "URL" => url = Some(value.into_owned()),
                            "Title" => title = Some(value.into_owned()),
                            "UserName" => username = Some(value.into_owned()),
                            "Password" => password = Some(value.into_owned()),
                            "Notes" => notes = Some(value.into_owned()),
                            _ => {}
                        }
                    }
                }
                "Tags" => {
                    if !child.children.is_empty() {
                        tags = Some(
                            child
                                .text_content()
                                .split(',')
                                .map(str::to_string)
                                .collect::<Vec<_>>(),
                        )
                    }
                }
                _ => {}
            };
        }
        Some(Self {
            uuid: uuid?,
            title: title?,
            url: url?,
            username: username?,
            password: password?,
            notes,
            tags,
        })
    }

    fn add_xml_children(&self, element: &mut Element, protected: &HashSet<&str>) {
        element.add_element("String", |el| {
            el.set_key_value(
                "URL".into(),
                self.url.as_str().into(),
                protected.contains("URL"),
            )
        });
        element.add_element("String", |el| {
            el.set_key_value(
                "Title".into(),
                self.title.as_str().into(),
                protected.contains("Title"),
            )
        });
        element.add_element("String", |el| {
            el.set_key_value(
                "UserName".into(),
                self.username.as_str().into(),
                protected.contains("UserName"),
            )
        });
        element.add_element("String", |el| {
            el.set_key_value(
                "Password".into(),
                self.password.as_str().into(),
                protected.contains("Password"),
            )
        });
        if let Some(notes) = &self.notes {
            element.add_element("String", |el| {
                el.set_key_value("Notes".into(), notes.into(), protected.contains("Notes"))
            });
        }
        if let Some(tags) = &self.tags {
            element.add_element("Tags", |el| el.set_text_content(tags.join(",").into()));
        }
    }

    pub fn to_xml(&self, protected: &HashSet<&str>) -> XMLNode {
        let mut element = Element::new("Entry");
        element.add_element("UUID", |el| el.set_text_content((&self.uuid).into()));
        self.add_xml_children(&mut element, protected);
        XMLNode::Element(element)
    }

    pub fn update_xml(&self, element: &mut Element, protected: &HashSet<&str>) {
        let fields = HashSet::from(["URL", "Title", "UserName", "Password", "Notes"]);
        element.children.retain(|child| {
            if let Some(element) = child.as_element() {
                if element.name == "String" {
                    if let Some((key, _)) = element.to_key_value() {
                        if fields.contains(key.as_ref()) {
                            return false;
                        }
                    }
                }
            }
            true
        });
        self.add_xml_children(element, protected);
    }

    pub fn hostname(&self) -> String {
        get_normalized_hostname(&self.url)
    }

    pub fn set_hostname(&mut self, hostname: String) {
        self.url = hostname;
        if !self.url.is_empty() {
            self.url.insert_str(0, "https://");
        }
    }
}
