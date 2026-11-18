use proxmox_http_error::HttpError;

use crate::Config;

/// Return all entities (targets, groups, filters) that are linked to the entity.
/// For instance, if a group 'grp1' contains the targets 'a', 'b' and 'c',
/// where grp1 has 'filter1' and 'a' has 'filter2' as filters, then
/// the result for 'grp1' would be [grp1, a, b, c, filter1, filter2].
/// The result will always contain the entity that was passed as a parameter.
/// If the entity does not exist, the result will only contain the entity.
pub fn get_referenced_entities(config: &Config, entity: &str) -> Result<Vec<String>, HttpError> {
    let entities = super::get_referenced_entities(config, entity);
    Ok(Vec::from_iter(entities))
}
