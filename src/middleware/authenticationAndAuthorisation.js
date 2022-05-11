const jwt = require("jsonwebtoken");
const validator = require("../validators/validator")

const authenticationUser = function (req, res, next) {
try {
    let token = req.headers["x-api-key"];
    if (!token) return res.status(400).send({ status: false, msg: "token must be present" });

    //verifying token with secret key
    let decodedToken = jwt.verify(token, "functionup-thorium-group5"); 

    //validating token value inside decodedToken
    if (!decodedToken)return res.status(401).send({ status: false, msg: "token is invalid" });
    
    req.authorId = decodedToken.authorId;

    next();
} catch (error) {
    res.status(500).send({ msg: "Error", error: error.message });
}
};

const authorisationUser = function (req, res, next) {
try {
    let authorisedUser = req.authorId
    let logedInUser = req.params.authorId;
    if(!validator.isValidObjectId(logedInUser)) return res.status(400).send({ status: false, message: "Please provide valid authorId" });

    if (authorisedUser !== logedInUser) return res.status(401).send({status: false,msg: "You are not an authorized person to make these changes"});
    next();
} catch (error) {
    return res.status(500).send({ msg: "Error", error: error.message });
}
};
module.exports = {authenticationUser, authorisationUser}