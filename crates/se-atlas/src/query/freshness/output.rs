//! Keep typed coverage and pagination honest when a cached revision is unverified.
use super::*;
pub(in crate::query) trait Verified: Sized {
    fn verify(self, verifier: &mut Verifier<'_, '_>) -> AtlasResult<Self>;
}
impl<T: Verified + Serialize> Verified for Page<T> {
    fn verify(self, verifier: &mut Verifier<'_, '_>) -> AtlasResult<Self> {
        let mut fields = self
            .window()
            .fields()
            .cloned()
            .ok_or_else(|| cache_error("query producer window is absent"))?;
        let next = self.next().cloned();
        let items = self
            .into_items()
            .into_iter()
            .map(|item| item.verify(verifier))
            .collect::<AtlasResult<Vec<_>>>()?;
        fields.bytes = items.iter().try_fold(0usize, |bytes, item| {
            Ok::<_, se_types::SeError>(bytes + size(item)?)
        })? as u64;
        if !verifier.reasons.is_empty() {
            fields.omitted_after = Omission::Unknown {
                reason: OmissionReason::SourceIncomplete,
            };
            if next.is_none() {
                fields.stop_reason = StopReason::Unsupported;
            }
        }
        Page::new(items, Window::new(fields)?, next)
    }
}
impl Verified for SearchResults {
    fn verify(mut self, verifier: &mut Verifier<'_, '_>) -> AtlasResult<Self> {
        self.page = self.page.verify(verifier)?;
        self.validate()?;
        Ok(self)
    }
}
impl Verified for SearchHit {
    fn verify(mut self, verifier: &mut Verifier<'_, '_>) -> AtlasResult<Self> {
        if let HitTarget::Code(code) = &mut self.target {
            // Full bodies already rehash the whole file and recheck the excerpt.
            let verified_body = self.body.as_ref().is_some_and(|body| matches!(
                &body.origin, BodyOrigin::LiveSource { content_hash: Some(hash), matches_index: Some(true), .. }
                    if Some(*hash) == code.pointer.content_hash));
            if !verified_body {
                verifier.pointer(&mut code.pointer)?;
            }
        }
        Ok(self)
    }
}
impl Verified for ReferenceHit {
    fn verify(mut self, verifier: &mut Verifier<'_, '_>) -> AtlasResult<Self> {
        if let ReferenceHit::Code(reference) = &mut self
            && verifier.pointer(&mut reference.site)?.is_some()
        {
            reference.accuracy = Accuracy::NameOnly;
            reference.resolved_target = None;
        }
        Ok(self)
    }
}
impl Verified for Dependent {
    fn verify(mut self, verifier: &mut Verifier<'_, '_>) -> AtlasResult<Self> {
        verifier.pointer(&mut self.pointer)?;
        for hop in &mut self.hops {
            if verifier.pointer(&mut hop.site)?.is_some() {
                hop.accuracy = Accuracy::NameOnly;
            }
        }
        for hop in &mut self.file_hops {
            if verifier.pointer(&mut hop.site)?.is_some() {
                hop.accuracy = Accuracy::NameOnly;
            }
        }
        Ok(self)
    }
}
impl Verified for Impact {
    fn verify(mut self, verifier: &mut Verifier<'_, '_>) -> AtlasResult<Self> {
        self.dependents = self
            .dependents
            .into_iter()
            .map(|v| v.verify(verifier))
            .collect::<AtlasResult<_>>()?;
        self.tests = self
            .tests
            .into_iter()
            .map(|v| v.verify(verifier))
            .collect::<AtlasResult<_>>()?;
        if !verifier.reasons.is_empty() {
            self.complete = false;
            self.frontier_count_complete = false;
        }
        Ok(self)
    }
}
impl Verified for Outline {
    fn verify(mut self, verifier: &mut Verifier<'_, '_>) -> AtlasResult<Self> {
        if let Some(reason) = verifier.pointer(&mut self.file)? {
            self.complete = false;
            if matches!(self.coverage, FileCoverage::Indexed) {
                self.coverage = FileCoverage::Partial {
                    reasons: vec![reason],
                };
            }
        }
        Ok(self)
    }
}
impl Verified for CodeChange {
    fn verify(mut self, verifier: &mut Verifier<'_, '_>) -> AtlasResult<Self> {
        if let CodeChange::Edit(edit) = &mut self
            && let Some(reason) = verifier.pointer(&mut edit.pointer)?
        {
            edit.dependents.complete = false;
            edit.dependents.reason = Some(reason);
        }
        Ok(self)
    }
}
