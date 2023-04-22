use std::borrow::Cow;
use xmltree::{Element, XMLNode};

pub(crate) trait XMLHelpers {
    fn index_of<P>(&self, predicate: P) -> Option<usize>
    where
        P: Fn(&Element) -> bool;
    fn elements(&self) -> ElementIterator<'_>;
    fn elements_mut(&mut self) -> Box<dyn Iterator<Item = &mut Element> + '_>;
    fn elements_recursive(&self) -> ElementIterator<'_>;
    fn modifier(&mut self) -> ElementModifier<'_>;
    fn text_content(&self) -> Cow<'_, str>;
    fn set_text_content(&mut self, text: Cow<'_, str>);
    fn to_boolean(&self) -> Option<bool>;
    fn to_key_value(&self) -> Option<(Cow<'_, str>, Cow<'_, str>)>;
    fn set_key_value(&mut self, key: Cow<'_, str>, value: Cow<'_, str>, protected: bool);
    fn add_element<I>(&mut self, name: &str, init: I)
    where
        I: FnOnce(&mut Self);
}

impl XMLHelpers for Element {
    fn index_of<P>(&self, predicate: P) -> Option<usize>
    where
        P: Fn(&Element) -> bool,
    {
        for (index, child) in self.children.iter().enumerate() {
            if let XMLNode::Element(element) = child {
                if predicate(element) {
                    return Some(index);
                }
            }
        }
        None
    }

    fn elements(&self) -> ElementIterator<'_> {
        ElementIterator::new(self).recurse_if(|_| false)
    }

    fn elements_mut(&mut self) -> Box<dyn Iterator<Item = &mut Element> + '_> {
        Box::new(
            self.children
                .iter_mut()
                .filter_map(|node| node.as_mut_element()),
        )
    }

    fn elements_recursive(&self) -> ElementIterator<'_> {
        ElementIterator::new(self)
    }

    fn modifier(&mut self) -> ElementModifier<'_> {
        ElementModifier::new(self)
    }

    fn text_content(&self) -> Cow<'_, str> {
        self.get_text().unwrap_or("".into())
    }

    fn set_text_content(&mut self, text: Cow<'_, str>) {
        self.children.clear();
        self.children.push(XMLNode::Text(text.into_owned()));
    }

    fn to_boolean(&self) -> Option<bool> {
        match self.text_content().as_ref() {
            "True" => Some(true),
            "true" => Some(true),
            "1" => Some(true),
            "False" => Some(false),
            "false" => Some(false),
            "0" => Some(false),
            _ => None,
        }
    }

    fn to_key_value(&self) -> Option<(Cow<'_, str>, Cow<'_, str>)> {
        let key = self.get_child("Key")?;
        let value = self.get_child("Value")?;
        Some((key.text_content(), value.text_content()))
    }

    fn set_key_value(&mut self, key: Cow<'_, str>, value: Cow<'_, str>, protected: bool) {
        if let Some(index) = self.index_of(|el| el.name == "Key") {
            self.children.remove(index);
        }
        if let Some(index) = self.index_of(|el| el.name == "Value") {
            self.children.remove(index);
        }

        self.add_element("Key", |el| el.set_text_content(key));
        self.add_element("Value", |el| {
            el.set_text_content(value);
            if protected {
                el.attributes
                    .insert("Protected".to_string(), "True".to_string());
            }
        });
    }

    fn add_element<I>(&mut self, name: &str, init: I)
    where
        I: FnOnce(&mut Self),
    {
        let mut element = Element::new(name);
        init(&mut element);
        self.children.push(XMLNode::Element(element));
    }
}

fn accept_all(_: &Element) -> bool {
    true
}

pub struct ElementIterator<'a> {
    accept_filter: Box<dyn Fn(&Element) -> bool>,
    recurse_filter: Box<dyn Fn(&Element) -> bool>,
    context: Option<&'a Element>,
    pos: usize,
    accepted_current: bool,
    stack: Vec<(&'a Element, usize)>,
}

impl<'a> ElementIterator<'a> {
    pub fn new(context: &'a Element) -> Self {
        Self {
            accept_filter: Box::new(accept_all),
            recurse_filter: Box::new(accept_all),
            context: Some(context),
            pos: 0,
            accepted_current: false,
            stack: Vec::new(),
        }
    }

    pub fn empty() -> Self {
        Self {
            accept_filter: Box::new(accept_all),
            recurse_filter: Box::new(accept_all),
            context: None,
            pos: 0,
            accepted_current: false,
            stack: Vec::new(),
        }
    }

    pub fn accept_if<P>(mut self, accept_filter: P) -> Self
    where
        P: Fn(&Element) -> bool + 'static,
    {
        self.accept_filter = Box::new(accept_filter);
        self
    }

    pub fn recurse_if<P>(mut self, recurse_filter: P) -> Self
    where
        P: Fn(&Element) -> bool + 'static,
    {
        self.recurse_filter = Box::new(recurse_filter);
        self
    }
}

impl<'a> Iterator for ElementIterator<'a> {
    type Item = &'a Element;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(context) = self.context {
            while self.pos < context.children.len() {
                if let XMLNode::Element(element) = &context.children[self.pos] {
                    if !self.accepted_current && (self.accept_filter)(element) {
                        self.accepted_current = true;
                        return Some(element);
                    }
                    self.accepted_current = false;

                    if (self.recurse_filter)(element) {
                        self.stack.push((context, self.pos));
                        self.context = Some(element);
                        self.pos = 0;
                        return self.next();
                    }
                }

                self.pos += 1;
            }

            if let Some((context, pos)) = self.stack.pop() {
                self.context = Some(context);
                self.pos = pos + 1;
                self.next()
            } else {
                None
            }
        } else {
            None
        }
    }
}

pub struct ElementModifier<'a> {
    accept_filter: Box<dyn Fn(&Element) -> bool>,
    recurse_filter: Box<dyn Fn(&Element) -> bool>,
    context: &'a mut Element,
}

impl<'a> ElementModifier<'a> {
    pub fn new(context: &'a mut Element) -> Self {
        Self {
            accept_filter: Box::new(accept_all),
            recurse_filter: Box::new(accept_all),
            context,
        }
    }

    pub fn accept_if<P>(mut self, accept_filter: P) -> Self
    where
        P: Fn(&Element) -> bool + 'static,
    {
        self.accept_filter = Box::new(accept_filter);
        self
    }

    pub fn recurse_if<P>(mut self, recurse_filter: P) -> Self
    where
        P: Fn(&Element) -> bool + 'static,
    {
        self.recurse_filter = Box::new(recurse_filter);
        self
    }

    pub fn modify<C, E>(&mut self, mut callback: C) -> Result<(), E>
    where
        C: FnMut(&mut Element) -> Result<(), E>,
    {
        Self::modify_impl(
            self.context,
            &self.accept_filter,
            &self.recurse_filter,
            &mut callback,
        )
    }

    fn modify_impl<C, E, A, R>(
        element: &mut Element,
        accept_filter: &A,
        recurse_filter: &R,
        callback: &mut C,
    ) -> Result<(), E>
    where
        C: FnMut(&mut Element) -> Result<(), E>,
        A: Fn(&Element) -> bool + 'static,
        R: Fn(&Element) -> bool + 'static,
    {
        if (accept_filter)(element) {
            callback(element)?;
        }

        if (recurse_filter)(element) {
            for child in element.elements_mut() {
                Self::modify_impl(child, accept_filter, recurse_filter, callback)?;
            }
        }

        Ok(())
    }
}
