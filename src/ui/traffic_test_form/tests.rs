use super::*;
use crate::domain::{TrafficSuiteId, TrafficSuiteRevision};

fn id() -> TrafficScenarioId {
    TrafficScenarioId::parse("scenario-1").unwrap()
}
fn valid() -> Draft {
    let mut draft = Draft::template(Template::Ssh);
    draft.source = "203.0.113.8".into();
    draft
}

#[test]
fn traffic_test_form_templates_require_explicit_source_and_never_enable_gates() {
    for (template, name, port, expectation, severity) in [
        (
            Template::Ssh,
            "Keep SSH access",
            "22",
            TrafficExpectation::Allow,
            TrafficSeverity::Critical,
        ),
        (
            Template::AllowService,
            "Allow service exposure",
            "",
            TrafficExpectation::Allow,
            TrafficSeverity::Advisory,
        ),
        (
            Template::BlockAccess,
            "Block unwanted access",
            "",
            TrafficExpectation::Block,
            TrafficSeverity::Advisory,
        ),
        (
            Template::Custom,
            "",
            "",
            TrafficExpectation::Allow,
            TrafficSeverity::Advisory,
        ),
    ] {
        let mut draft = Draft::template(template);
        assert_eq!(draft.name, name);
        assert_eq!(draft.destination_port, port);
        assert_eq!(draft.expectation, expectation);
        assert_eq!(draft.severity, severity);
        assert!(draft.source.is_empty());
        assert_eq!(draft.ingress, 0);
        assert!(draft.ingress_value.is_empty());
        assert!(draft.enabled);
        assert!(draft.scenario(id()).is_err());
        draft.name = "Explicit name".into();
        draft.source = "203.0.113.8".into();
        draft.destination_port = "443".into();
        let scenario = draft.scenario(id()).unwrap();
        assert!(!scenario.required_safety_gate);
        assert_eq!(scenario.direction, TrafficDirection::ToHost);
        assert_eq!(scenario.connection_state, TrafficConnectionState::New);
        assert_eq!(scenario.destination, TrafficDestination::LocalHost);
    }
}

#[test]
fn traffic_test_form_typed_source_ports_and_text_boundaries() {
    for source in [
        "203.0.113.8",
        "192.0.2.0/24",
        "2001:db8::1",
        "2001:db8::/32",
    ] {
        let mut draft = valid();
        draft.source = source.into();
        draft.destination_port = "8000-8010".into();
        draft.source_port = "1024".into();
        assert!(draft.scenario(id()).is_ok(), "valid source {source}");
    }
    for source in ["", "garbage", "aa:bb:cc:dd:ee:ff", "ipset:trusted"] {
        let mut draft = valid();
        draft.source = source.into();
        assert!(draft.scenario(id()).is_err());
    }
    for port in ["0", "65536", "90-80", "22/tcp", ""] {
        let mut draft = valid();
        draft.destination_port = port.into();
        assert!(draft.scenario(id()).is_err());
    }
    let mut draft = valid();
    draft.name = "é".repeat(64);
    draft.note = "é".repeat(512);
    assert!(draft.scenario(id()).is_ok());
    draft.name.push('a');
    assert!(draft.scenario(id()).is_err());
    draft.name.pop();
    draft.note.push('a');
    assert!(draft.scenario(id()).is_err());
}

#[test]
fn traffic_test_form_transport_and_ingress_are_exclusive() {
    for transport in [0, 1, 2, 3] {
        let mut draft = valid();
        draft.transport = transport;
        if transport > 1 {
            draft.destination_port.clear();
            draft.icmp = "echo-request".into();
            draft.protocol = "gre".into();
        }
        let scenario = draft.scenario(id()).unwrap();
        assert!(matches!(
            (transport, scenario.transport),
            (0, TrafficTransport::Tcp)
                | (1, TrafficTransport::Udp)
                | (2, TrafficTransport::Icmp { .. })
                | (3, TrafficTransport::RawProtocol { .. })
        ));
        assert_eq!(
            draft.fields().contains(&Field::DestinationPort),
            transport < 2
        );
        assert_eq!(draft.fields().contains(&Field::Icmp), transport == 2);
        assert_eq!(draft.fields().contains(&Field::Protocol), transport == 3);
        if transport > 1 {
            draft.source_port = "22".into();
            assert!(
                draft.scenario(id()).is_err(),
                "stale ports must be rejected"
            );
        }
    }
    for (mode, value) in [(0, "ignored"), (1, "public"), (2, "eth0")] {
        let mut draft = valid();
        draft.ingress = mode;
        draft.ingress_value = value.into();
        let scenario = draft.scenario(id()).unwrap();
        assert_eq!(scenario.ingress_zone.is_some(), mode == 1);
        assert_eq!(scenario.ingress_interface.is_some(), mode == 2);
        assert_eq!(draft.fields().contains(&Field::IngressValue), mode != 0);
    }
}

#[test]
fn traffic_test_form_input_caps_and_transport_cycle_clear_irrelevant_fields() {
    let mut draft = valid();
    draft.name.clear();
    for _ in 0..100 {
        draft.input('é');
    }
    assert_eq!(draft.name.len(), 128);
    draft.backspace();
    assert_eq!(draft.name.len(), 126);
    draft.focus = draft
        .fields()
        .iter()
        .position(|f| *f == Field::Note)
        .unwrap();
    for _ in 0..1100 {
        draft.input('a');
    }
    assert_eq!(draft.note.len(), 1024);
    draft.input('\n');
    assert_eq!(draft.note.len(), 1024);
    draft.focus = draft
        .fields()
        .iter()
        .position(|f| *f == Field::Transport)
        .unwrap();
    draft.source_port = "23".into();
    draft.cycle(1);
    draft.cycle(1);
    assert_eq!(draft.transport, 2);
    assert!(draft.destination_port.is_empty() && draft.source_port.is_empty());
}

fn suite() -> TrafficSuite {
    TrafficSuite {
        id: TrafficSuiteId::parse("default").unwrap(),
        name: "Original suite".into(),
        revision: TrafficSuiteRevision::new(7).unwrap(),
        scenarios: vec![valid().scenario(id()).unwrap()],
    }
}

#[test]
fn traffic_test_form_suite_edits_preserve_identity_order_and_bound_new_ids() {
    let mut base = suite();
    let next = prepare(&base, &valid()).unwrap();
    assert_eq!(next.scenarios.len(), 2);
    assert_eq!(next.scenarios[1].id.as_str(), "scenario-2");
    assert_eq!(
        (&next.id, &next.name, next.revision),
        (&base.id, &base.name, base.revision)
    );
    assert_eq!(next.scenarios[0], base.scenarios[0]);
    base.scenarios[0].required_safety_gate = true;
    let mut draft = Draft::edit(&base.scenarios[0]);
    draft.name = "Renamed".into();
    let edited = prepare(&base, &draft).unwrap();
    assert_eq!(edited.scenarios.len(), 1);
    assert_eq!(edited.scenarios[0].id, base.scenarios[0].id);
    assert!(edited.scenarios[0].required_safety_gate);
    for index in 2..=MAX_SCENARIOS_PER_SUITE {
        let mut scenario = base.scenarios[0].clone();
        scenario.id = TrafficScenarioId::parse(&format!("scenario-{index}")).unwrap();
        base.scenarios.push(scenario);
    }
    assert!(prepare(&base, &valid()).is_err());
    assert!(prepare(&base, &draft).is_ok());
}

#[test]
fn traffic_test_form_reserved_inputs_are_preserved_exactly() {
    for direction in [
        TrafficDirection::ToHost,
        TrafficDirection::FromHost,
        TrafficDirection::Forwarded,
    ] {
        for connection_state in [
            TrafficConnectionState::New,
            TrafficConnectionState::Established,
            TrafficConnectionState::Related,
        ] {
            let mut original = valid().scenario(id()).unwrap();
            original.direction = direction;
            original.connection_state = connection_state;
            original.required_safety_gate = true;
            original.destination =
                TrafficDestination::Address(SourceAddress::parse("192.0.2.1").unwrap());
            original.egress_zone = Some(ZoneName::parse("public").unwrap());
            let mut draft = Draft::edit(&original);
            assert!(draft.metadata_only());
            assert_eq!(
                draft.fields(),
                vec![Field::Name, Field::Severity, Field::Enabled, Field::Note]
            );
            draft.name = "Metadata update".into();
            draft.note = "Preserved inputs".into();
            draft.enabled = false;
            draft.source = "invalid injected input".into();
            let edited = draft.scenario(id()).unwrap();
            original.name = draft.name;
            original.note = Some(draft.note);
            original.enabled = false;
            assert_eq!(edited, original);
        }
    }
}

#[test]
fn traffic_test_form_render_keeps_last_field_and_review_line_reachable() {
    use crate::ui::theme::Theme;
    use ratatui::{Terminal, backend::TestBackend};
    let theme = Theme::new(crate::ui::theme::Variant::Mono, false, false);
    for (width, height) in [(80, 24), (120, 40), (160, 50)] {
        let mut draft = valid();
        draft.note = "last note field ".repeat(40);
        draft.focus = draft.fields().len() - 1;
        let base = Arc::new(suite());
        let candidate = Arc::new(prepare(&base, &draft).unwrap());
        let mut editor = Editor {
            creating_suite: false,
            base,
            draft,
            candidate: Some(candidate),
            stage: Stage::Draft,
            kind: EditKind::Form,
            dirty: true,
            accepted: false,
            error: None,
            discard: None,
            scroll: 0,
        };
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| render::render(frame, &mut editor, &theme, frame.area()))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        assert!(
            text.contains("> Note"),
            "focused note missing at {width}x{height}"
        );
        editor.stage = Stage::Review;
        editor.scroll = u16::MAX;
        terminal
            .draw(|frame| render::render(frame, &mut editor, &theme, frame.area()))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        assert!(
            text.contains("Save local file only"),
            "last review line missing at {width}x{height}"
        );
        assert!(text.contains("y Save"));
        editor.scroll = 0;
        terminal
            .draw(|frame| render::render(frame, &mut editor, &theme, frame.area()))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        assert!(text.contains("Configuration evaluation"));
        assert!(text.contains("Live connectivity: NOT VERIFIED"));
    }
}

#[test]
fn traffic_test_form_render_shows_input_tail_cursor_and_reserved_warning() {
    use crate::ui::theme::{Theme, Variant};
    use ratatui::{Terminal, backend::TestBackend};
    let theme = Theme::new(Variant::Mono, false, false);
    for (width, height) in [(80, 24), (120, 40), (160, 50)] {
        let mut draft = valid();
        draft.note = format!("{}TAIL-END", "x".repeat(1016));
        draft.focus = draft.fields().len() - 1;
        let mut editor = Editor {
            creating_suite: false,
            base: Arc::new(suite()),
            draft,
            candidate: None,
            stage: Stage::Draft,
            kind: EditKind::Form,
            dirty: true,
            accepted: false,
            error: None,
            discard: None,
            scroll: 0,
        };
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| render::render(frame, &mut editor, &theme, frame.area()))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        assert!(text.contains("> Note"));
        assert!(
            text.contains("TAIL-END"),
            "input tail hidden at {width}x{height}"
        );
        let cursor = terminal.get_cursor_position().unwrap();
        assert!(
            cursor.x > 0 && cursor.y > 0 && cursor.y < height - 2,
            "cursor must track visible input"
        );
        let mut scenario = valid().scenario(id()).unwrap();
        scenario.direction = TrafficDirection::FromHost;
        editor.draft = Draft::edit(&scenario);
        terminal
            .draw(|frame| render::render(frame, &mut editor, &theme, frame.area()))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        assert!(
            text.contains("Reserved inputs preserved"),
            "reserved warning hidden"
        );
    }
}
