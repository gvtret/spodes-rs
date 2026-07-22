//! Meter data-exchange tasks (СТО 34.01-5.1-013-2023, §10.7, `0.0.94.7.133.255`).
//!
//! Read/write/action jobs the ИВКЭ runs against meters, held as a `Data` (IC 1)
//! object whose value is an `array exchange` (§10.7):
//!
//! ```text
//! exchange ::= structure {
//!     task_id: long-unsigned,
//!     meter-id: array octet-string,
//!     array script {
//!         service_id, class_id, obis, index,
//!         range_descriptor: structure || null-data,
//!         entry_descriptor: structure || null-data,
//!         value: attribute-specific || null-data
//!     },
//!     execution_type: enum,
//!     execution_time: array { time: octet-string, date: octet-string },
//!     priority: long-unsigned
//! }
//! ```

use crate::classes::data::Data;
use crate::types::CosemDataType;

use super::obis;

/// `service_id` values of a task script (§10.7).
pub mod service_id {
    /// GET service.
    pub const GET: u8 = 1;
    /// SET service.
    pub const SET: u8 = 2;
    /// ACTION service.
    pub const ACTION: u8 = 3;
}

/// One meter object access within a task (§10.7, `script`).
#[derive(Clone, Debug, Default)]
pub struct Script {
    /// Service to invoke (see [`service_id`]).
    pub service_id: u8,
    /// Class id of the target object.
    pub class_id: u8,
    /// OBIS of the target object.
    pub obis: Vec<u8>,
    /// Attribute or method index.
    pub index: u8,
    /// Selective-access range descriptor, or `None`.
    pub range_descriptor: Option<CosemDataType>,
    /// Selective-access entry descriptor, or `None`.
    pub entry_descriptor: Option<CosemDataType>,
    /// Value for SET/ACTION, or `None`.
    pub value: Option<CosemDataType>,
}

impl Script {
    fn to_structure(&self) -> CosemDataType {
        let opt = |v: &Option<CosemDataType>| v.clone().unwrap_or(CosemDataType::Null);
        CosemDataType::Structure(vec![
            CosemDataType::Unsigned(self.service_id),
            CosemDataType::Unsigned(self.class_id),
            CosemDataType::OctetString(self.obis.clone()),
            CosemDataType::Unsigned(self.index),
            opt(&self.range_descriptor),
            opt(&self.entry_descriptor),
            opt(&self.value),
        ])
    }
}

/// One scheduled execution time (§10.7, `execution_time_date`).
#[derive(Clone, Debug, Default)]
pub struct ExecutionTime {
    /// Time octets.
    pub time: Vec<u8>,
    /// Date octets.
    pub date: Vec<u8>,
}

/// One data-exchange task (§10.7, `exchange`).
#[derive(Clone, Debug, Default)]
pub struct ExchangeTask {
    /// Task identifier.
    pub task_id: u32,
    /// Meters the task applies to (empty = the task is disabled).
    pub meter_ids: Vec<Vec<u8>>,
    /// The object accesses to run.
    pub scripts: Vec<Script>,
    /// Execution type (as `single action schedule` type, IC 22).
    pub execution_type: u8,
    /// Scheduled execution times.
    pub execution_times: Vec<ExecutionTime>,
    /// Execution priority (ascending order).
    pub priority: u16,
}

impl ExchangeTask {
    fn to_structure(&self) -> CosemDataType {
        let meter_ids = self.meter_ids.iter().map(|m| CosemDataType::OctetString(m.clone())).collect();
        let scripts = self.scripts.iter().map(Script::to_structure).collect();
        let times = self
            .execution_times
            .iter()
            .map(|t| {
                CosemDataType::Structure(vec![
                    CosemDataType::OctetString(t.time.clone()),
                    CosemDataType::OctetString(t.date.clone()),
                ])
            })
            .collect();
        // task_id is practically always <=u16::MAX (a concentrator won't
        // schedule 65536+ tasks); the wire field is long-unsigned regardless
        // of the wider in-memory type.
        #[allow(clippy::cast_possible_truncation)]
        let task_id = self.task_id as u16;
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(task_id),
            CosemDataType::Array(meter_ids),
            CosemDataType::Array(scripts),
            CosemDataType::Enum(self.execution_type),
            CosemDataType::Array(times),
            CosemDataType::LongUnsigned(self.priority),
        ])
    }
}

/// The data-exchange task list (§10.7, `0.0.94.7.133.255`).
#[derive(Clone, Debug, Default)]
pub struct ExchangeTasks {
    tasks: Vec<ExchangeTask>,
}

impl ExchangeTasks {
    /// Creates an empty task list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a task.
    pub fn add(&mut self, task: ExchangeTask) {
        self.tasks.push(task);
    }

    /// Finds a task by id.
    pub fn find(&self, task_id: u32) -> Option<&ExchangeTask> {
        self.tasks.iter().find(|t| t.task_id == task_id)
    }

    /// Builds the COSEM `Data` (IC 1) object holding the task array (§10.7).
    pub fn build(&self) -> Data {
        let array = self.tasks.iter().map(ExchangeTask::to_structure).collect();
        Data::new(obis::data_exchange_tasks(), CosemDataType::Array(array))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::InterfaceClass;

    #[test]
    fn exchange_tasks_build_data_object() {
        let mut tasks = ExchangeTasks::new();
        tasks.add(ExchangeTask {
            task_id: 7,
            meter_ids: vec![b"SIT12260004".to_vec()],
            scripts: vec![Script {
                service_id: service_id::GET,
                class_id: 1,
                obis: vec![1, 0, 1, 8, 0, 255],
                index: 2,
                ..Default::default()
            }],
            execution_type: 0,
            execution_times: vec![ExecutionTime { time: vec![0, 0, 0, 0], date: vec![0xFF; 5] }],
            priority: 1,
        });

        assert_eq!(tasks.find(7).unwrap().priority, 1);
        assert!(tasks.find(9).is_none());

        let object = tasks.build();
        assert_eq!(object.class_id(), 1);
        assert_eq!(object.logical_name(), &obis::data_exchange_tasks());
        let CosemDataType::Array(rows) = &object.attributes()[1].1 else { panic!("array") };
        assert_eq!(rows.len(), 1);
        let CosemDataType::Structure(fields) = &rows[0] else { panic!("exchange structure") };
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0], CosemDataType::LongUnsigned(7));
        // scripts array with one script of seven fields.
        let CosemDataType::Array(scripts) = &fields[2] else { panic!("scripts array") };
        let CosemDataType::Structure(script) = &scripts[0] else { panic!("script structure") };
        assert_eq!(script.len(), 7);
        assert_eq!(script[0], CosemDataType::Unsigned(service_id::GET));
        // absent optional fields are null-data.
        assert_eq!(script[4], CosemDataType::Null);
    }
}
