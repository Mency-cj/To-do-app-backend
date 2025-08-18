const { PrismaClient } = require("./generated/prisma");
const express = require("express");
const cors = require('cors');
const jwt = require("jsonwebtoken");
const app = express();
const bcrypt = require('bcrypt');
const prisma = new PrismaClient();
app.use(express.json());
app.use(cors());

 const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization?req.headers.authorization:  req.query.token;
    if (!authHeader) {
        return res.status(401).json({ success: false, error: 'Token not Found' });
    } else {
        const token = authHeader && authHeader.split(" ")[1];
        if (token == null) {
            return res.status(401).json({ success: false, error: 'Token not Found' });
        } else {
            jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
                if (err) {
                    return res.status(403).json({ success: false, error: 'Invalid token' });
                }
                req.user = user;
                if(Date.now() >= user.exp * 1000)
                {
                    return res.status(401).json({ success: false, error: 'Token Expired!' });
                }
                else{
                    next();
                }   
            });
        }
    }
}

app.post("/signup", async (req, res) => {
  const { email, password, name } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email,
         password:hashedPassword,
          name },
    });
          const token = jwt.sign(
        {id:user.id},
        process.env.JWT_SECRET,
        {expiresIn:"1h"}
      )

    res.status(200).json({success: true,message: "sign-up successful",token});
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ success: false, error: "User registration failed" });
  }
});

app.post("/login",async(req,res)=>{
  const{email,password} = req.body;
  try{
    const user=await prisma.user.findUnique({
      where:{email}});
      if(!user){
        return res.status(400).json({ success: false, error: "User not found" });
      }
      const isMatch = await bcrypt.compare(password,user.password);
      if(!isMatch){
        return res.status(400).json({ success: false, error: "Invalid credentials" });
      }
      const token = jwt.sign(
        {id:user.id},
        process.env.JWT_SECRET,
        {expiresIn:"1h"}
      )
          res.status(200).json({success: true,message: "Login successful",token});
  }
  catch(error){console.error(error);
    res.status(500).json({ success: false, error: "Server error" });}
});

app.post("/todo",authenticateToken,async (req,res) => {
  const{task,isCompleted}=req.body;
  try{
    const newTask = await prisma.task.create({
      data:{userId:req.user.id,
        task,isCompleted},
    });
    res.status(201).json({success:true,newTask});
  }
  catch(error){
    console.error("Error creating task:",error);
    res.status(500).json({success:false,error:"Adding task failed"});
  }
});

app.get("/todo",authenticateToken,async (req,res) => {
  try{
    const tasks = await prisma.task.findMany({
      where:{userId:req.user.id},
      orderBy:{id:'desc'}
    });
    res.status(200).json({success:true,tasks});
  }
  catch(error){
    console.error("Error creating task:",error);
    res.status(500).json({success:false,error:"Adding task failed"});
  }
});

app.patch("/todo/:id", async (req, res) => {
  const { id } = req.params;
  const { isCompleted } = req.body;


  try {
    const updatedTask = await prisma.task.update({
      where: { id: parseInt(id, 10) },
      data: { isCompleted},
    });
    res.status(200).json({ success: true, updatedTask });
  } 
  catch(error){
    console.error("Error updating task:",error);
    res.status(500).json({success:false,error:"updating task failed"});
  }
});

app.delete("/todo/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const deleteTask = await prisma.task.delete({
      where: { id: parseInt(id) },
    });
    res.status(200).json({ success: true, deleteTask });
  } 
  catch(error){
    console.error("Error deleting task:",error);
    res.status(500).json({success:false,error:"deleting task failed"});
  }
});

app.listen(5000, () => console.log("Server running on http://localhost:5000"));