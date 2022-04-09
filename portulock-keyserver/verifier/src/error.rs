use anyhow::Error;
use rocket::response::Responder;
use rocket::Request;

pub struct AnyhowErrorResponse(anyhow::Error);

impl<'r, 'o: 'r> Responder<'r, 'o> for AnyhowErrorResponse {
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'o> {
        error!("ERROR_RESPONSE: {:#?}", self.0);
        // TODO consider logging the request as well
        let message = format!("Unspecified Error: {:#?}", self.0);
        rocket::response::status::Custom(rocket::http::Status::InternalServerError, message).respond_to(request)
    }
}

impl From<anyhow::Error> for AnyhowErrorResponse {
    fn from(e: Error) -> Self {
        AnyhowErrorResponse(e)
    }
}
