use std::io::{Read, Write};

use crate::action::Action;
use crate::error::Error;
use crate::response::{ActionResponse, ErrorResponse, Response};

fn error_response(request_id: String, err: Error) -> ActionResponse {
    ActionResponse {
        request_id,
        success: false,
        response: Response::Error(ErrorResponse {
            error: format!("{err}"),
            error_code: err.code(),
        }),
    }
}

pub(crate) fn run_server() -> Result<(), Error> {
    let mut stdin = io_streams::StreamReader::stdin()?;
    let mut stdout = io_streams::StreamWriter::stdout()?;

    loop {
        let size = {
            let mut buffer = [0; 4];
            stdin.read_exact(&mut buffer)?;
            u32::from_ne_bytes(buffer) as usize
        };

        let message = {
            let mut buffer = Vec::new();
            buffer.resize(size, 0);
            stdin.read_exact(&mut buffer)?;
            buffer
        };

        let response = {
            match serde_json::from_slice::<Action>(&message) {
                Ok(action) => {
                    let request_id = action.request_id.clone();

                    match crate::action_handler::handle(action) {
                        Ok(response) => ActionResponse {
                            request_id,
                            success: true,
                            response,
                        },
                        Err(error) => error_response(request_id, error),
                    }
                }
                Err(_) => error_response(String::from(""), Error::InvalidMessage),
            }
        };

        let stringified = serde_json::to_vec(&response)?;
        let out_size = stringified.len() as u32;
        stdout.write_all(&out_size.to_ne_bytes())?;
        stdout.write_all(&stringified)?;
    }
}
