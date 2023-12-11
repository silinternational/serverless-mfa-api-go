package api

// swagger:model
type ApiKeyCreateInput struct {
	Email string `json:"email" form:"email" binding:"required" validate:"email"`
}

// swagger:model
type ApiKeyActivateInput struct {
	ApiKey string `json:"apiKeyValue" form:"apiKeyValue" binding:"required"`
	Email  string `json:"email" form:"email" binding:"required" validate:"email"`
}

// swagger:model
type ApiKeyActivateOutput struct {
	Secret string `json:"apiSecret"`
}
